package auth

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	confirmedPairingPrefix = "ARK:AUTH:CONFIRMEDPAIR:"
	pairingDevicePrefix    = "ARK:AUTH:PAIRDEVICE:"
)

// DevicePairing lives in Redis after explicit account confirmation. Its stable
// credential is committed only when the device exchanges the temporary token.
type DevicePairing struct {
	UserID         int64   `json:"userId"`
	DeviceID       string  `json:"deviceId"`
	TempToken      string  `json:"tempToken"`
	SecretToken    string  `json:"secretToken"`
	PreviousSecret *string `json:"previousSecret"`
	RequestID      string  `json:"requestId,omitempty"`
	Challenge      string  `json:"challenge,omitempty"`
	Attempted      bool    `json:"attempted"`
}

var confirmPairingScript = redis.NewScript(`
local old = redis.call('GET', KEYS[1])
if old then
  redis.call('DEL', ARGV[4] .. old)
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
return 1
`)

// IssueConfirmedPairingToken is called only by explicit account confirmation.
// A later confirmation for this device invalidates the previous account's
// pending token. It never changes a previously committed device binding.
func (s *TokenService) IssueConfirmedPairingToken(ctx context.Context, userID int64, deviceID string, previousSecret *string) (string, error) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	p := DevicePairing{UserID: userID, DeviceID: deviceID, TempToken: token, SecretToken: uuid.NewString(), PreviousSecret: previousSecret}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	err = confirmPairingScript.Run(ctx, s.rdb,
		[]string{pairingDevicePrefix + deviceID, confirmedPairingPrefix + token},
		token, string(body), int(pairingTokenTTL.Seconds()), confirmedPairingPrefix).Err()
	return token, err
}

var exchangeConfirmedPairingScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
local p = cjson.decode(raw)
if redis.call('GET', ARGV[1] .. p.deviceId) ~= p.tempToken then return nil end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return nil end
if not p.attempted then
  p.attempted = true
  redis.call('PSETEX', KEYS[1], ttl, cjson.encode(p))
end
return raw
`)

// ExchangeConfirmedPairingToken returns the cached, stable credential on
// retries without extending the confirmation deadline. Only the first attempt
// may create a device row; retries cannot recreate an explicitly unbound device.
// OAuth-only and legacy session-shaped tokens cannot enter this flow.
func (s *TokenService) ExchangeConfirmedPairingToken(ctx context.Context, token string) (*DevicePairing, error) {
	raw, err := exchangeConfirmedPairingScript.Run(ctx, s.rdb,
		[]string{confirmedPairingPrefix + token}, pairingDevicePrefix).Text()
	return decodeDevicePairing(raw, err)
}

func decodeDevicePairing(raw string, err error) (*DevicePairing, error) {
	if errors.Is(err, redis.Nil) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	var p DevicePairing
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, ErrInvalidToken
	}
	if p.UserID <= 0 || p.DeviceID == "" || p.TempToken == "" || p.SecretToken == "" {
		return nil, ErrInvalidToken
	}
	return &p, nil
}

// BindingRequest contains no device secret. Its callback and challenge are
// immutable for the lifetime of the request; approval never extends that life.
type BindingRequest struct {
	RequestID string `json:"requestId"`
	DeviceID  string `json:"deviceId"`
	ReturnTo  string `json:"deviceReturnTo"`
	Challenge string `json:"challenge"`
}

const bindingRequestPrefix = "ARK:AUTH:BINDING:"

func (s *TokenService) CreateBindingRequest(ctx context.Context, deviceID, callback, challenge string) (*BindingRequest, error) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return nil, err
	}
	p := &BindingRequest{hex.EncodeToString(b), deviceID, callback, challenge}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	return p, s.rdb.Set(ctx, bindingRequestPrefix+p.RequestID, body, 5*time.Minute).Err()
}
func (s *TokenService) BindingRequest(ctx context.Context, id string) (*BindingRequest, error) {
	if len(id) != 64 {
		return nil, ErrInvalidToken
	}
	raw, err := s.rdb.Get(ctx, bindingRequestPrefix+id).Bytes()
	if err != nil {
		return nil, ErrInvalidToken
	}
	var p BindingRequest
	if json.Unmarshal(raw, &p) != nil {
		return nil, ErrInvalidToken
	}
	return &p, nil
}

var approveBindingScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return nil end
local old = redis.call('GET', KEYS[2])
if old then
 local p = cjson.decode(old)
 if p.userId ~= tonumber(ARGV[1]) then return nil end
 return old
end
redis.call('PSETEX', KEYS[2], ttl, ARGV[2])
redis.call('PSETEX', KEYS[3], ttl, ARGV[2])
return ARGV[2]
`)

func (s *TokenService) ApproveBinding(ctx context.Context, request *BindingRequest, userID int64) (*DevicePairing, error) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return nil, err
	}
	p := DevicePairing{UserID: userID, DeviceID: request.DeviceID, TempToken: hex.EncodeToString(b), SecretToken: uuid.NewString(), RequestID: request.RequestID, Challenge: request.Challenge}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	raw, err := approveBindingScript.Run(ctx, s.rdb, []string{bindingRequestPrefix + request.RequestID, bindingRequestPrefix + request.RequestID + ":approved", confirmedPairingPrefix + p.TempToken}, userID, string(body)).Text()
	return decodeDevicePairing(raw, err)
}

var exchangeProtectedPairingScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
local p = cjson.decode(raw)
if not p.challenge or p.challenge ~= ARGV[1] or p.requestId ~= ARGV[2] then return nil end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return nil end
if not p.attempted then
 p.attempted = true
 redis.call('PSETEX', KEYS[1], math.min(ttl, 60000), cjson.encode(p))
end
return raw
`)

func (s *TokenService) ExchangeProtectedPairingToken(ctx context.Context, token, requestID, verifier string) (*DevicePairing, error) {
	b, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != verifier || len(token) != 64 || len(requestID) != 64 {
		return nil, ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	raw, err := exchangeProtectedPairingScript.Run(ctx, s.rdb, []string{confirmedPairingPrefix + token}, challenge, requestID).Text()
	return decodeDevicePairing(raw, err)
}

var bindingRateScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end
return n
`)

func (s *TokenService) AllowBindingRequest(ctx context.Context, source string) bool {
	digest := sha256.Sum256([]byte(source))
	n, err := bindingRateScript.Run(ctx, s.rdb, []string{"ARK:AUTH:BINDRATE:" + hex.EncodeToString(digest[:])}).Int()
	return err == nil && n <= 30
}

// Status lookups use a separate bucket so polling cannot exhaust creation quota.
func (s *TokenService) AllowBindingStatus(ctx context.Context, source string) bool {
	digest := sha256.Sum256([]byte(source))
	n, err := bindingRateScript.Run(ctx, s.rdb, []string{"ARK:AUTH:BINDSTATUSRATE:" + hex.EncodeToString(digest[:])}).Int()
	return err == nil && n <= 60
}

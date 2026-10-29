package auth

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"

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

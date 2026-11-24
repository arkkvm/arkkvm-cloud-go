// Package auth replaces Sa-Token (doc 04): opaque tokens stored in Redis with
// the same semantics as the legacy configuration — 30-day TTL, single session
// per user (a new login revokes the old token), and an optional per-session
// "device" attribute used by the device pairing tempToken flow.
package auth

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrInvalidToken = errors.New("invalid token")

const (
	tokenKeyPrefix   = "ARK:AUTH:TOKEN:"   // token -> session JSON
	userKeyPrefix    = "ARK:AUTH:USER:"    // userID -> current token (single-session enforcement)
	pairingKeyPrefix = "ARK:AUTH:PAIR:"    // pairing token -> pairing JSON (non-session)
	mcpCodeKeyPrefix = "ARK:AUTH:MCPCODE:" // one-time MCP grant code -> grant JSON (non-session)

	SessionTTL      = 30 * 24 * time.Hour // sa-token timeout: 2592000s
	mcpGrantCodeTTL = 10 * time.Minute
)

type session struct {
	UserID int64  `json:"userId"`
	Device string `json:"device,omitempty"` // empty = plain web login; non-empty = pairing tempToken
}

// loginScript revokes any existing session for the user, then records the new
// token and the user->token mapping atomically (single-session semantics).
// KEYS[1] = user key, KEYS[2] = token key prefix,
// ARGV[1] = session JSON, ARGV[2] = new token, ARGV[3] = TTL seconds.
// Lua must end with an explicit return: a script returning nothing yields a
// nil reply, which go-redis surfaces as the redis.Nil error.
var loginScript = redis.NewScript(`
local old = redis.call('GET', KEYS[1])
if old then redis.call('DEL', KEYS[2] .. old) end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[2] .. ARGV[2], ARGV[1], 'EX', ARGV[3])
return old or ''
`)

// logoutScript deletes the token key and the user->token index, but only when
// the index still points at this token (a concurrent re-login must survive).
// KEYS[1] = token key, KEYS[2] = user key, ARGV[1] = token.
var logoutScript = redis.NewScript(`
redis.call('DEL', KEYS[1])
local cur = redis.call('GET', KEYS[2])
if cur == ARGV[1] then redis.call('DEL', KEYS[2]) end
return 1
`)

type TokenService struct {
	// OnRevoked is installed at startup. Receives only the displaced/revoked token.
	OnRevoked func(string)
	rdb       *redis.Client
	ttl       time.Duration
	jwtSecret []byte
}

// NewTokenService issues tokens in the legacy Sa-Token JWT shape
// ({"typ":"JWT","alg":"HS256"}.{"loginType":"login","loginId":N,"rnStr":...}.sig,
// signed with the same HS256 secret as the Java deployment). The server itself
// treats the token as an opaque string — validity always comes from Redis —
// but device firmware and web clients parse it, so the shape must not drift.
func NewTokenService(rdb *redis.Client, jwtSecret string) *TokenService {
	return &TokenService{rdb: rdb, ttl: SessionTTL, jwtSecret: []byte(jwtSecret)}
}

func (s *TokenService) signJWT(userID int64) string {
	header := `{"typ":"JWT","alg":"HS256"}`
	payload := fmt.Sprintf(`{"loginType":"login","loginId":%d,"rnStr":"%s"}`, userID, randomRNStr())
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, s.jwtSecret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

const rnStrAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randomRNStr mirrors the legacy rnStr: 32 alphanumeric characters.
func randomRNStr() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = rnStrAlphabet[rand.Intn(len(rnStrAlphabet))]
	}
	return string(b)
}

// Login creates a session. device is the empty string for a plain web login,
// or the deviceId when issuing a pairing tempToken. A previous session for the
// same user (if any) is revoked.
func (s *TokenService) Login(ctx context.Context, userID int64, device string) (string, error) {
	token := s.signJWT(userID)
	body, err := json.Marshal(session{UserID: userID, Device: device})
	if err != nil {
		return "", err
	}
	old, err := loginScript.Run(ctx, s.rdb,
		[]string{userKey(userID), tokenKeyPrefix},
		string(body), token, fmt.Sprintf("%d", int(s.ttl.Seconds())),
	).Text()
	if err != nil {
		return "", err
	}
	if old != "" && s.OnRevoked != nil {
		s.OnRevoked(old)
	}
	return token, nil
}

// Resolve returns (userID, device) for a token, or ErrInvalidToken.
func (s *TokenService) Resolve(ctx context.Context, token string) (int64, string, error) {
	if token == "" {
		return 0, "", ErrInvalidToken
	}
	val, err := s.rdb.Get(ctx, tokenKeyPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return 0, "", ErrInvalidToken
	}
	if err != nil {
		return 0, "", err
	}
	var sess session
	if err := json.Unmarshal([]byte(val), &sess); err != nil {
		return 0, "", ErrInvalidToken
	}
	return sess.UserID, sess.Device, nil
}

// ResolveDevice maps a pairing tempToken to its deviceId, mirroring the legacy
// StpUtil.getLoginDeviceTypeByToken used by POST /devices/token.
func (s *TokenService) ResolveDevice(ctx context.Context, token string) (string, error) {
	_, device, err := s.Resolve(ctx, token)
	if err != nil {
		return "", err
	}
	if device == "" {
		return "", ErrInvalidToken
	}
	return device, nil
}

const pairingTokenTTL = 10 * time.Minute

type pairing struct {
	UserID   int64  `json:"userId"`
	DeviceID string `json:"deviceId"`
}

// IssuePairingToken preserves the OAuth callback's legacy redirect shape with
// a short-lived, non-session placeholder. It does not authorize device token
// exchange: only IssueConfirmedPairingToken, called after explicit account
// confirmation, can do that. Web login does not revoke this placeholder.
func (s *TokenService) IssuePairingToken(ctx context.Context, userID int64, deviceID string) (string, error) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	body, err := json.Marshal(pairing{UserID: userID, DeviceID: deviceID})
	if err != nil {
		return "", err
	}
	if err := s.rdb.Set(ctx, pairingKeyPrefix+token, body, pairingTokenTTL).Err(); err != nil {
		return "", err
	}
	return token, nil
}

// ResolvePairingToken maps a pairing token to (userID, deviceId). Read-only:
// the caller revokes via RevokePairingToken only after a successful key
// exchange, so a firmware retry after a network failure still finds it.
func (s *TokenService) ResolvePairingToken(ctx context.Context, token string) (int64, string, error) {
	if token == "" {
		return 0, "", ErrInvalidToken
	}
	val, err := s.rdb.Get(ctx, pairingKeyPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return 0, "", ErrInvalidToken
	}
	if err != nil {
		return 0, "", err
	}
	var p pairing
	if err := json.Unmarshal([]byte(val), &p); err != nil {
		return 0, "", ErrInvalidToken
	}
	return p.UserID, p.DeviceID, nil
}

// RevokePairingToken deletes a consumed pairing token (idempotent).
func (s *TokenService) RevokePairingToken(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.rdb.Del(ctx, pairingKeyPrefix+token).Err()
}

type mcpGrant struct {
	UserID    int64  `json:"userId"`
	Req       string `json:"req"`
	Challenge string `json:"challenge,omitempty"`
}

// consumeScript atomically reads and burns a one-time grant code: the code
// dies the moment it is read, whether or not the req binding matches (a
// wrong guess gets one shot). KEYS[1] = code key.
var consumeScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v then redis.call('DEL', KEYS[1]) end
return v
`)

// IssueMcpGrantCode mints the one-time MCP grant code (doc 16 §1): bound to
// the (userID, req) pair — req is the MCP-generated random echoed through
// the login redirect. Production exchange additionally requires S256 PKCE.
// 10-minute TTL, single-use; no session is minted here.
func (s *TokenService) IssueMcpGrantCode(ctx context.Context, userID int64, req, challenge string) (string, error) {
	if userID <= 0 || req == "" || len(req) > 128 || !ValidMcpChallenge(challenge) {
		return "", ErrInvalidToken
	}
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	code := hex.EncodeToString(b)
	body, err := json.Marshal(mcpGrant{UserID: userID, Req: req, Challenge: challenge})
	if err != nil {
		return "", err
	}
	if err := s.rdb.Set(ctx, mcpCodeKeyPrefix+code, body, mcpGrantCodeTTL).Err(); err != nil {
		return "", err
	}
	return code, nil
}

// Logout deletes the session behind a token (idempotent).
func (s *TokenService) Logout(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	// Fetch the session first to learn the userId for the reverse index.
	val, err := s.rdb.Get(ctx, tokenKeyPrefix+token).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return err
	}
	var sess session
	if err := json.Unmarshal([]byte(val), &sess); err != nil {
		return ErrInvalidToken
	}
	err = logoutScript.Run(ctx, s.rdb,
		[]string{tokenKeyPrefix + token, userKey(sess.UserID)},
		token,
	).Err()
	if err == nil && s.OnRevoked != nil {
		s.OnRevoked(token)
	}
	return err
}

func userKey(userID int64) string { return fmt.Sprintf("%s%d", userKeyPrefix, userID) }

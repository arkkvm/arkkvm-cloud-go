package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The token string must stay byte-compatible with the legacy Sa-Token JWT
// shape: three base64url segments, header {"typ":"JWT","alg":"HS256"},
// payload {"loginType":"login","loginId":<number>,"rnStr":"<32 alnum>"},
// HS256 signature verifiable with the configured secret (device firmware and
// web clients parse and possibly verify it).
func TestSignJWTShape(t *testing.T) {
	ts := &TokenService{jwtSecret: []byte("unit-test-jwt-signing-key")}
	token := ts.signJWT(6)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token must have 3 segments, got %d", len(parts))
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header not base64url: %v", err)
	}
	if string(header) != `{"typ":"JWT","alg":"HS256"}` {
		t.Fatalf("unexpected header: %s", header)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload not base64url: %v", err)
	}
	var claims struct {
		LoginType string `json:"loginType"`
		LoginID   int64  `json:"loginId"`
		RNStr     string `json:"rnStr"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if claims.LoginType != "login" || claims.LoginID != 6 || len(claims.RNStr) != 32 {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// The observed legacy token used exactly this encoding of the header.
	if parts[0] != "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" {
		t.Fatalf("header segment must match the legacy Sa-Token encoding, got %s", parts[0])
	}
}

func TestSignJWTUniqueness(t *testing.T) {
	ts := &TokenService{jwtSecret: []byte("k")}
	if ts.signJWT(1) == ts.signJWT(1) {
		t.Fatal("two tokens for the same user must differ (rnStr)")
	}
}

package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func TestGenerateCredentialsStaticFallback(t *testing.T) {
	// No Cloudflare key and no self-hosted TURN: the static STUN list is
	// returned as-is, no credentials attached — the console gates its
	// WebSocket on this endpoint, so the STUN-only posture must answer.
	svc := NewTurnService(TurnConfig{StaticStun: []string{"stun:stun.arkkvm.cn:3478"}})
	ice, err := svc.GenerateCredentials(context.Background())
	if err != nil {
		t.Fatalf("static fallback returned error: %v", err)
	}
	if len(ice.URLs) != 1 || ice.URLs[0] != "stun:stun.arkkvm.cn:3478" {
		t.Fatalf("unexpected static urls: %v", ice.URLs)
	}
	if ice.Username != "" || ice.Credential != "" {
		t.Fatalf("static fallback must not carry credentials: %q/%q", ice.Username, ice.Credential)
	}
}

func TestGenerateCredentialsStaticEmpty(t *testing.T) {
	// Nothing configured at all: a hard error (the handler surfaces its
	// failure envelope) — an empty answer would silently break clients.
	svc := NewTurnService(TurnConfig{})
	if _, err := svc.GenerateCredentials(context.Background()); err == nil {
		t.Fatal("expected error when no issuer is configured")
	}
}

func TestGenerateCredentialsSelfHosted(t *testing.T) {
	// CN posture: coturn REST credentials — username = expiry unix seconds,
	// credential = base64(HMAC-SHA1(secret, username)); the exact contract
	// exercised against the deployed coturn with turnutils_uclient. The
	// configured STUN entries ride in front of the TURN urls (parity with
	// the Cloudflare stun+turn shape).
	const secret = "shared-secret-for-tests"
	svc := NewTurnService(TurnConfig{
		StaticStun:         []string{"stun:stun.arkkvm.cn:3478"},
		SelfHostedSecret:   secret,
		SelfHostedTurnURLs: []string{"turn:stun.arkkvm.cn:3478?transport=udp", "turn:stun.arkkvm.cn:3478?transport=tcp"},
	})
	before := time.Now().Unix()
	ice, err := svc.GenerateCredentials(context.Background())
	if err != nil {
		t.Fatalf("self-hosted issuer returned error: %v", err)
	}
	after := time.Now().Unix()

	if len(ice.URLs) != 3 ||
		ice.URLs[0] != "stun:stun.arkkvm.cn:3478" ||
		ice.URLs[1] != "turn:stun.arkkvm.cn:3478?transport=udp" ||
		ice.URLs[2] != "turn:stun.arkkvm.cn:3478?transport=tcp" {
		t.Fatalf("unexpected ice urls (stun must precede turn): %v", ice.URLs)
	}
	expiry, err := strconv.ParseInt(ice.Username, 10, 64)
	if err != nil {
		t.Fatalf("username is not a plain expiry timestamp: %q", ice.Username)
	}
	if expiry < before+3600-1 || expiry > after+3600+1 {
		t.Fatalf("expiry %d outside [%d, %d]", expiry, before+3600-1, after+3600+1)
	}
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(ice.Username))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if ice.Credential != want {
		t.Fatalf("credential mismatch: got %q want %q", ice.Credential, want)
	}
}

func TestGenerateCredentialsCloudflareWinsOverSelfHosted(t *testing.T) {
	// A deployment with a Cloudflare key must keep using it even if a
	// self-hosted secret is also present (priority order is explicit).
	svc := NewTurnService(TurnConfig{
		CloudflareKeyID:    "key-id",
		SelfHostedSecret:   "s",
		SelfHostedTurnURLs: []string{"turn:stun.arkkvm.cn:3478"},
	})
	// No HTTP stub: the Cloudflare path is taken, and the request fails fast
	// against the unreachable test endpoint — the error text identifies it.
	_, err := svc.GenerateCredentials(context.Background())
	if err == nil {
		t.Fatal("expected the cloudflare path to be taken (request error)")
	}
}

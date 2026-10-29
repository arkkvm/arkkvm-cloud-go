package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestTokenService(t *testing.T) *TokenService {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewTokenService(rdb, "test-secret")
}

// F5 relies on this semantic: after Logout the pairing tempToken can no
// longer resolve a device, so consuming it at /devices/token kills reuse.
func TestLogoutInvalidatesDeviceToken(t *testing.T) {
	ts := newTestTokenService(t)
	ctx := context.Background()

	tempToken, err := ts.Login(ctx, 6, "dev-1")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if dev, err := ts.ResolveDevice(ctx, tempToken); err != nil || dev != "dev-1" {
		t.Fatalf("resolveDevice before logout: dev=%q err=%v", dev, err)
	}

	if err := ts.Logout(ctx, tempToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := ts.ResolveDevice(ctx, tempToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("resolveDevice after logout must fail with ErrInvalidToken, got %v", err)
	}
}

// A plain web-login token (empty device) must not resolve as a device token.
func TestResolveDeviceRejectsWebSession(t *testing.T) {
	ts := newTestTokenService(t)
	ctx := context.Background()

	webToken, err := ts.Login(ctx, 6, "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := ts.ResolveDevice(ctx, webToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("web token must not resolve a device, got %v", err)
	}
}

// The pairing token is a non-session credential: it coexists with
// the user's web session instead of kicking it, never resolves as a session,
// and only dies on an explicit revoke (resolve is read-only so a firmware
// retry after a network failure still finds it).
func TestPairingTokenLifecycle(t *testing.T) {
	ts := newTestTokenService(t)
	ctx := context.Background()

	pairingToken, err := ts.IssuePairingToken(ctx, 6, "dev-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pairingToken == "" {
		t.Fatal("pairing token must not be empty")
	}
	// Two pairing tokens for the same user must coexist (no single-session
	// slot involved), and minting one must not touch existing sessions.
	second, err := ts.IssuePairingToken(ctx, 6, "dev-2")
	if err != nil || second == pairingToken {
		t.Fatalf("second pairing token: %q err=%v", second, err)
	}
	webToken, err := ts.Login(ctx, 6, "")
	if err != nil {
		t.Fatalf("web login: %v", err)
	}
	if uid, dev, err := ts.ResolvePairingToken(ctx, pairingToken); err != nil || uid != 6 || dev != "dev-1" {
		t.Fatalf("resolve after login: (%d,%q) err=%v — web login must not kick pairing tokens", uid, dev, err)
	}
	if _, _, err := ts.Resolve(ctx, pairingToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("pairing token must NOT resolve as a session, got %v", err)
	}
	if _, err := ts.ResolveDevice(ctx, pairingToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("pairing token must NOT resolve as a legacy session device token, got %v", err)
	}
	// Resolve is read-only; only Revoke consumes it.
	if err := ts.RevokePairingToken(ctx, pairingToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := ts.ResolvePairingToken(ctx, pairingToken); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("resolve after revoke must fail with ErrInvalidToken, got %v", err)
	}
	if err := ts.RevokePairingToken(ctx, pairingToken); err != nil {
		t.Fatalf("revoke must be idempotent: %v", err)
	}
	if uid, _, err := ts.Resolve(ctx, webToken); err != nil || uid != 6 {
		t.Fatalf("web session must stay live throughout: (%d) %v", uid, err)
	}
}

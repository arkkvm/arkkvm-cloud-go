package ws

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
)

// fakeMcpResolver stands in for *auth.McpTokenService.
type fakeMcpResolver struct{ tokens map[string]int64 }

func (f *fakeMcpResolver) Resolve(_ context.Context, token string) (int64, error) {
	if uid, ok := f.tokens[token]; ok {
		return uid, nil
	}
	return 0, auth.ErrInvalidToken
}

// The signaling handshake resolves the web session first (unchanged
// semantics) and falls back to the MCP credential only on failure
//.
func TestClientEndpointResolveUserIDFallback(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	tokens := auth.NewTokenService(rdb, "k")
	session, err := tokens.Login(context.Background(), 42, "")
	if err != nil {
		t.Fatal(err)
	}

	e := &ClientEndpoint{
		Tokens:    tokens,
		McpTokens: &fakeMcpResolver{tokens: map[string]int64{"mcp-tok": 7}},
	}
	if uid, err := e.resolveUserID(context.Background(), session); err != nil || uid != 42 {
		t.Fatalf("session must resolve to 42, got (%d, %v)", uid, err)
	}
	if uid, err := e.resolveUserID(context.Background(), "mcp-tok"); err != nil || uid != 7 {
		t.Fatalf("mcp token must resolve via fallback to 7, got (%d, %v)", uid, err)
	}
	if _, err := e.resolveUserID(context.Background(), "junk"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("junk must fail, err = %v", err)
	}
}

// Without the optional resolver wired, behavior is exactly the legacy one:
// sessions work, everything else is rejected.
func TestClientEndpointResolveUserIDWithoutMcp(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	tokens := auth.NewTokenService(rdb, "k")
	session, err := tokens.Login(context.Background(), 42, "")
	if err != nil {
		t.Fatal(err)
	}

	e := &ClientEndpoint{Tokens: tokens}
	if uid, err := e.resolveUserID(context.Background(), session); err != nil || uid != 42 {
		t.Fatalf("session must resolve to 42, got (%d, %v)", uid, err)
	}
	if _, err := e.resolveUserID(context.Background(), "mcp-tok"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("mcp token must fail without the resolver, err = %v", err)
	}
}

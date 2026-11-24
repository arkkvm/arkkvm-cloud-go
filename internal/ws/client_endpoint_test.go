package ws

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"

	"arkkvm.com/arkkvm-cloud/internal/auth"
)

func TestSignalingCredentialSources(t *testing.T) {
	for _, tc := range []struct {
		name, query, protocols, want string
		legacy                       bool
	}{
		{"legacy cannot be reenabled", "token=old", "", "", true},
		{"legacy disabled", "token=old", "", "", false},
		{"duplicate query", "token=one&token=two", "", "", true},
		{"missing", "", "", "", true},
		{"empty query", "token=", "", "", true},
		{"retired subprotocol", "", "arkkvm-signaling-v1, arkkvm-auth.synthetic", "", true},
		{"query mixed with retired protocol", "token=old", "arkkvm-auth.synthetic", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://localhost/?"+tc.query, nil)
			if tc.protocols != "" {
				r.Header.Set("Sec-WebSocket-Protocol", tc.protocols)
			}
			endpoint := ClientEndpoint{}
			got, _, err := endpoint.signalingHandshakeCredential(r)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatal("unexpected credential policy")
			}
		})
	}
}

type signalingDeviceStore struct{ allowed bool }

func (s signalingDeviceStore) BelongsToUser(context.Context, string, int64) (bool, error) {
	return s.allowed, nil
}

type signalingUserStore struct{}

func (signalingUserStore) OIDCToken(context.Context, int64) (string, error) { return "", nil }

func TestSignalingWebSocketCompatibility(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	tokens := auth.NewTokenService(rdb, "test-key")
	session, err := tokens.Login(context.Background(), 42, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                        string
		legacy, query, mcp, allowed bool
		status                      int
	}{
		{"cookie strict", false, false, false, true, 101},
		{"cookie compatible", true, false, false, true, 101},
		{"old compatible now rejected", true, true, false, true, 401},
		{"old disabled", false, true, false, true, 401},
		{"MCP header", false, false, true, true, 101},
		{"wrong owner", false, false, false, false, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			hub := NewHub(log, nil)
			hub.RegisterDevice(&DeviceConn{SessionAuthLease: true, DeviceID: "dev-test", DeviceVersion: "test"})
			e := &ClientEndpoint{Hub: hub, Tokens: tokens, McpTokens: &fakeMcpResolver{tokens: map[string]int64{"mcp-test": 7}}, Devices: signalingDeviceStore{tc.allowed}, Users: signalingUserStore{}, Log: log, Lifetime: context.Background(), AllowedReturnURLs: []string{"https://app.arkkvm.com/ad-login"}, Options: Options{SendBuffer: 8, WriteTimeout: time.Second, ReadDeadline: time.Second, MaxMessageSize: 4096}}
			srv := httptest.NewServer(e)
			defer srv.Close()
			token := session
			if tc.mcp {
				token = "mcp-test"
			}
			role := RoleUser
			if tc.mcp {
				role = RoleAgent
			}
			address := "ws" + strings.TrimPrefix(srv.URL, "http") + "?id=dev-test&clientType=" + role
			headers := http.Header{}
			if tc.query {
				address += "&token=" + token
			} else if tc.mcp {
				headers.Set("Authorization", "Bearer "+token)
				headers.Set("Cookie", auth.BrowserSessionCookieName+"="+session)
			} else {
				headers.Set("Origin", "https://app.arkkvm.com")
				headers.Set("Cookie", auth.BrowserSessionCookieName+"="+token)
			}
			conn, resp, err := websocket.DefaultDialer.Dial(address, headers)
			if resp == nil {
				t.Fatalf("missing response: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d want=%d", resp.StatusCode, tc.status)
			}
			if tc.status != 101 {
				if conn != nil {
					conn.Close()
					t.Fatal("unauthorized upgrade")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if conn.Subprotocol() != "" {
				t.Fatal("credentials must not use the response protocol")
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			_, payload, err := conn.ReadMessage()
			if err != nil || !strings.Contains(string(payload), "device-metadata") {
				t.Fatalf("metadata: %v", err)
			}
			if err = conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				t.Fatal(err)
			}
			_, payload, err = conn.ReadMessage()
			if err != nil || string(payload) != "pong" {
				t.Fatalf("heartbeat: %v", err)
			}
		})
	}
}

// fakeMcpResolver stands in for *auth.McpTokenService.
type fakeMcpResolver struct{ tokens map[string]int64 }

func (f *fakeMcpResolver) Resolve(_ context.Context, token string) (int64, error) {
	if uid, ok := f.tokens[token]; ok {
		return uid, nil
	}
	return 0, auth.ErrInvalidToken
}

// Even valid old credentials cannot reopen URL authentication, with or without MCP wiring.
func TestRetiredURLCredentialsWithOrWithoutMcp(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	tokens := auth.NewTokenService(rdb, "test-key")
	session, err := tokens.Login(context.Background(), 42, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, wired := range []bool{false, true} {
		e := &ClientEndpoint{Tokens: tokens, AllowedReturnURLs: []string{"https://app.arkkvm.com/ad-login"}}
		if wired {
			e.McpTokens = &fakeMcpResolver{tokens: map[string]int64{"mcp-tok": 7}}
		}
		for _, token := range []string{session, "mcp-tok", "junk", auth.BrowserSessionReference(session)} {
			for _, cookie := range []bool{false, true} {
				r := httptest.NewRequest("GET", "https://api.arkkvm.com/?token="+token, nil)
				if cookie {
					r.Header.Set("Origin", "https://app.arkkvm.com")
					r.AddCookie(&http.Cookie{Name: auth.BrowserSessionCookieName, Value: session})
				}
				if _, _, err := e.signalingHandshakeCredential(r); err == nil {
					t.Fatal("retired URL credential accepted")
				}
			}
		}
		r := httptest.NewRequest("GET", "https://api.arkkvm.com/?id=device", nil)
		r.Header.Set("Origin", "https://app.arkkvm.com")
		r.AddCookie(&http.Cookie{Name: auth.BrowserSessionCookieName, Value: session})
		value, kind, err := e.signalingHandshakeCredential(r)
		if err != nil || value != session || kind != signalingSessionCredential {
			t.Fatal("valid Cookie rejected")
		}
	}
}

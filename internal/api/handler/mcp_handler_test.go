package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"arkkvm.com/arkkvm-cloud/internal/auth"
	"arkkvm.com/arkkvm-cloud/internal/model"
)

// memMcpStore is an in-memory auth.McpTokenStore (hash -> row).
type memMcpStore struct {
	rows map[string]*model.McpToken
	next int64
}

func newMemMcpStore() *memMcpStore { return &memMcpStore{rows: map[string]*model.McpToken{}} }

func (s *memMcpStore) Create(t *model.McpToken) error {
	s.next++
	t.ID = s.next
	now := time.Now()
	t.CreatedAt, t.UpdatedAt = now, now
	s.rows[t.TokenHash] = t
	return nil
}

func (s *memMcpStore) FindActiveByHash(hash string) (*model.McpToken, error) {
	t, ok := s.rows[hash]
	if !ok || t.RevokedAt != nil {
		return nil, model.ErrMcpTokenNotFound
	}
	return t, nil
}

func (s *memMcpStore) TouchLastUsed(id int64, now time.Time) error {
	for _, t := range s.rows {
		if t.ID == id {
			t.LastUsedAt = &now
		}
	}
	return nil
}

func (s *memMcpStore) Revoke(id int64, now time.Time) error {
	for _, t := range s.rows {
		if t.ID == id && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

type mcpHarness struct {
	srv    *httptest.Server
	tokens *auth.TokenService
	mcp    *auth.McpTokenService
	store  *memMcpStore
	mr     *miniredis.Miniredis
}

func newMcpHarness(t *testing.T) *mcpHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	tokens := auth.NewTokenService(rdb, "test-secret")
	store := newMemMcpStore()
	mcp := auth.NewMcpTokenService(store)
	h := NewMcpHandler(tokens, mcp)
	r := gin.New()
	r.POST("/mcp/token", h.ExchangeToken)
	r.POST("/mcp/revoke", auth.RequireMcp(mcp), h.Revoke)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &mcpHarness{srv: srv, tokens: tokens, mcp: mcp, store: store, mr: mr}
}

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// seedGrantCode mints a grant code via the same call the OAuth callback uses.
func (h *mcpHarness) seedGrantCode(t *testing.T, userID int64, req string) string {
	t.Helper()
	code, err := h.tokens.IssueMcpGrantCode(context.Background(), userID, req, testMcpChallenge())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestMcpTokenExchangeHappyPath(t *testing.T) {
	h := newMcpHarness(t)
	code := h.seedGrantCode(t, 42, "req-1")

	resp := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-1","codeVerifier":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, code))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var br BaseResult[struct {
		Token     string `json:"token"`
		TokenType string `json:"tokenType"`
	}]
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		t.Fatal(err)
	}
	if !br.Success || br.Data.Token == "" || br.Data.TokenType != "mcp" {
		t.Fatalf("envelope: %+v", br)
	}
	// The minted token is a live MCP credential — and NOT a web session.
	if uid, err := h.mcp.Resolve(context.Background(), br.Data.Token); err != nil || uid != 42 {
		t.Fatalf("mcp token must resolve to 42, got (%d, %v)", uid, err)
	}
	if _, _, err := h.tokens.Resolve(context.Background(), br.Data.Token); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("mcp token must NOT be a user session, resolve err = %v", err)
	}
}

func TestMcpTokenExchangeUnknownCode(t *testing.T) {
	h := newMcpHarness(t)
	resp := postJSON(t, h.srv.URL+"/mcp/token", `{"code":"deadbeef","req":"req-1"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

// A wrong req burns the code (the consume is atomic and unconditional), so a
// guessing attacker gets exactly one shot per code — even with the right req
// on a retry.
func TestMcpTokenExchangeWrongReqBurnsCode(t *testing.T) {
	h := newMcpHarness(t)
	code := h.seedGrantCode(t, 42, "req-1")

	resp := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-wrong"}`, code))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong req must 401, got %d", resp.StatusCode)
	}
	retry := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-1","codeVerifier":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, code))
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusUnauthorized {
		t.Fatalf("code must be burned by the failed attempt, got %d", retry.StatusCode)
	}
}

func TestMcpTokenExchangeExpired(t *testing.T) {
	h := newMcpHarness(t)
	code := h.seedGrantCode(t, 42, "req-1")
	h.mr.FastForward(11 * time.Minute)

	resp := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-1","codeVerifier":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, code))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired code must 401, got %d", resp.StatusCode)
	}
}

func TestMcpTokenExchangeMalformed(t *testing.T) {
	h := newMcpHarness(t)
	for _, body := range []string{`{}`, `{"code":"x"}`, `{"req":"y"}`, `not-json`} {
		resp := postJSON(t, h.srv.URL+"/mcp/token", body)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("body %q: want 401, got %d", body, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestMcpRevokeFlow(t *testing.T) {
	h := newMcpHarness(t)
	code := h.seedGrantCode(t, 42, "req-1")
	exchange := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-1","codeVerifier":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, code))
	var br BaseResult[struct{ Token string }]
	if err := json.NewDecoder(exchange.Body).Decode(&br); err != nil {
		t.Fatal(err)
	}
	exchange.Body.Close()
	token := br.Data.Token
	notified := make(chan string, 1)
	h.mcp.OnRevoked = func(value string) { notified <- value }

	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp/revoke", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke must 200, got %d", resp.StatusCode)
	}
	select {
	case value := <-notified:
		if value != token {
			t.Fatal("wrong credential invalidation")
		}
	default:
		t.Fatal("revoke did not notify active sessions")
	}

	if _, err := h.mcp.Resolve(context.Background(), token); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revoked token must stop resolving, err = %v", err)
	}

	// Once revoked the token can no longer authenticate the endpoint (the
	// middleware rejects it before the handler), and garbage is 401 too —
	// idempotency lives at the service level.
	for _, bearer := range []string{token, "garbage"} {
		r2, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp/revoke", nil)
		r2.Header.Set("Authorization", "Bearer "+bearer)
		resp2, err := h.srv.Client().Do(r2)
		if err != nil {
			t.Fatal(err)
		}
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("dead/garbage bearer must 401 on /mcp/revoke, got %d for %q", resp2.StatusCode, bearer)
		}
		resp2.Body.Close()
	}
	// Service-level revoke stays idempotent (no error on dead/unknown).
	if err := h.mcp.Revoke(context.Background(), token); err != nil {
		t.Fatalf("service-level revoke must be idempotent: %v", err)
	}
}

// A web session must never be able to revoke MCP credentials — the endpoint
// is MCP-credential-only by design.
func TestMcpRevokeRejectsSessionAndAnonymous(t *testing.T) {
	h := newMcpHarness(t)
	session, err := h.tokens.Login(context.Background(), 42, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, bearer := range map[string]string{"session": session, "anonymous": ""} {
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/mcp/revoke", nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := h.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s must 401 on /mcp/revoke, got %d", name, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func testMcpChallenge() string {
	sum := sha256.Sum256([]byte(strings.Repeat("a", 43)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestMcpExchangeRequiresProof(t *testing.T) {
	for _, verifier := range []string{"", strings.Repeat("b", 43)} {
		h := newMcpHarness(t)
		code := h.seedGrantCode(t, 42, "req-1")
		response := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-1","codeVerifier":%q}`, code, verifier))
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Fatalf("proof bypass: %d", response.StatusCode)
		}
		retry := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-1","codeVerifier":%q}`, code, strings.Repeat("a", 43)))
		retry.Body.Close()
		if retry.StatusCode != 401 {
			t.Fatal("failed proof must burn code")
		}
	}
}

func TestMcpExchangeRejectsOldGrant(t *testing.T) {
	h := newMcpHarness(t)
	code := "old-grant"
	if err := h.mr.Set("ARK:AUTH:MCPCODE:"+code, `{"userId":42,"req":"req-1"}`); err != nil {
		t.Fatal(err)
	}

	response := postJSON(t, h.srv.URL+"/mcp/token", fmt.Sprintf(`{"code":%q,"req":"req-1","codeVerifier":%q}`, code, strings.Repeat("a", 43)))
	defer response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("old grant accepted")
	}
}

func TestMcpTokenAbsoluteExpiry(t *testing.T) {
	h := newMcpHarness(t)
	token, err := h.mcp.Issue(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range h.store.rows {
		row.CreatedAt = time.Now().Add(-auth.McpTokenMaxTTL - time.Second)
		now := time.Now()
		row.LastUsedAt = &now
	}
	if _, err := h.mcp.Resolve(context.Background(), token); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatal("expired token accepted or renewed by usage")
	}
	if _, err := h.mcp.Resolve(context.Background(), strings.Repeat("a", 64)); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatal("old token accepted")
	}
}

func TestMcpTokenIdleExpiryAndRenewal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		age, idle time.Duration
		valid     bool
	}{
		{"idle beyond seven days", 10 * 24 * time.Hour, 8 * 24 * time.Hour, false},
		{"recent use extends initial seven days", 10 * 24 * time.Hour, 24 * time.Hour, true},
		{"absolute cap despite recent use", 31 * 24 * time.Hour, time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMcpHarness(t)
			token, err := h.mcp.Issue(context.Background(), 42)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range h.store.rows {
				row.CreatedAt = time.Now().Add(-tc.age)
				last := time.Now().Add(-tc.idle)
				row.LastUsedAt = &last
			}
			_, err = h.mcp.Resolve(context.Background(), token)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid {
				for _, row := range h.store.rows {
					if time.Since(*row.LastUsedAt) > time.Minute {
						t.Fatal("successful use not renewed")
					}
				}
			}
		})
	}
}

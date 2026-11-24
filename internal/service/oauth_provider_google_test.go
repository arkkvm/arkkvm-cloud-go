package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func goldGoogleCfg() GoogleProviderConfig {
	return GoogleProviderConfig{
		ClientID:      "g-client-id",
		ClientSecret:  "g-secret",
		RedirectURI:   "{baseUrl}/oauth2/code/google",
		Scope:         "openid email profile",
		AuthURI:       "https://accounts.test/auth",
		TokenURI:      "https://tokens.test/token", // replaced per-test
		JWKSURI:       "https://jwks.test/certs",
		VerifyIDToken: false,
	}
}

func TestGoogleAuthURLStateAndNonce(t *testing.T) {
	p := NewGoogleProvider(goldGoogleCfg(), nil, nil)
	u, _ := url.Parse(p.AuthURL("https://app.example.com", "browser-state"))
	if !p.RequiresState() || u.Query().Get("state") != "browser-state" || u.Query().Get("nonce") != GoogleNonce("browser-state") {
		t.Fatal("Google must bind authorization to state and nonce")
	}
	if u.Query().Get("prompt") != "consent" || u.Query().Get("client_id") != "g-client-id" {
		t.Fatal("legacy authorization parameters changed")
	}
}

func unsignedIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// GOLDEN: the token exchange form must carry exactly the legacy fields, as a
// form POST to the configured token URI.
func TestGoogleExchangeFormGolden(t *testing.T) {
	var gotForm url.Values
	var gotCT, gotAccept string
	signer := newTestRSAKey(t)
	jwks := signer.jwksServer(t)
	defer jwks.Close()
	idToken := signer.sign(t, map[string]any{
		"iss": "https://accounts.google.com", "aud": "g-client-id", "exp": time.Now().Add(time.Hour).Unix(), "nonce": GoogleNonce("state"),
		"sub": "sub-1", "email": "u@example.com", "email_verified": true, "picture": "https://p/x.png", "name": "Google User",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		gotCT = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","id_token":"` + idToken + `"}`))
	}))
	defer srv.Close()

	cfg := goldGoogleCfg()
	cfg.TokenURI = srv.URL
	cfg.JWKSURI = jwks.URL
	p := NewGoogleProvider(cfg, srv.Client(), nil)

	ident, err := p.Exchange(WithGoogleState(context.Background(), "state"), "the-code", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type = %q", gotCT)
	}
	if gotAccept != "" {
		t.Fatalf("google exchange must not set Accept (legacy parity), got %q", gotAccept)
	}
	for k, want := range map[string]string{
		"code":          "the-code",
		"client_id":     "g-client-id",
		"client_secret": "g-secret",
		"redirect_uri":  "https://app.example.com/oauth2/code/google",
		"grant_type":    "authorization_code",
	} {
		if gotForm.Get(k) != want {
			t.Errorf("form[%s] = %q, want %q", k, gotForm.Get(k), want)
		}
	}
	if len(gotForm) != 5 {
		t.Errorf("form must carry exactly 5 fields, got %d (%v)", len(gotForm), gotForm)
	}
	if ident.ProviderUserID != "sub-1" || ident.Email != "u@example.com" ||
		!ident.EmailVerified || ident.AvatarURL != "https://p/x.png" || ident.DisplayName != "Google User" {
		t.Fatalf("identity mapping drifted: %+v", ident)
	}
	if ident.RawIDToken != idToken {
		t.Fatalf("RawIDToken must preserve the google id_token for the oidc_token double-write")
	}
}

func TestGoogleVerificationFailsClosed(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := goldGoogleCfg()
		cfg.VerifyIDToken = enabled
		cfg.JWKSURI = "http://127.0.0.1:0/certs"
		p := NewGoogleProvider(cfg, nil, nil)
		if claims, err := p.parseIDToken(unsignedIDToken(t, map[string]any{"sub": "s"})); err == nil || claims != nil {
			t.Fatal("signature verification failure must not return claims, even with legacy verification switch disabled")
		}
	}
}

// Reproduce the reported C4 input through the complete exchange path rather
// than only calling the parser: a successful token response, invalid ID token,
// and an unavailable verification key must never produce an identity.
func TestGoogleExchangeRejectsReportedC4Scenario(t *testing.T) {
	jwks := httptest.NewServer(http.NotFoundHandler())
	defer jwks.Close()
	idToken := unsignedIDToken(t, map[string]any{"sub": "c4-test", "exp": int64(1)})
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
	}))
	defer tokenEndpoint.Close()
	for _, enabled := range []bool{true, false} {
		cfg := goldGoogleCfg()
		cfg.TokenURI, cfg.JWKSURI, cfg.VerifyIDToken = tokenEndpoint.URL, jwks.URL, enabled
		p := NewGoogleProvider(cfg, nil, nil)
		ident, err := p.Exchange(WithGoogleState(context.Background(), "test-state"), "test-code", "https://app.example.com")
		if err == nil || ident != nil {
			t.Fatalf("verify=%v: reported C4 input returned an identity", enabled)
		}
		if googleFailureReason(err) != "jwks_http_failure" {
			t.Fatalf("verify=%v: expected rejection at JWKS verification, got %v", enabled, err)
		}
	}
}

func TestGoogleClaimsValidation(t *testing.T) {
	signer := newTestRSAKey(t)
	jwks := signer.jwksServer(t)
	defer jwks.Close()
	cfg := goldGoogleCfg()
	cfg.JWKSURI = jwks.URL
	p := NewGoogleProvider(cfg, nil, nil)
	for _, tc := range []struct {
		name  string
		field string
		value any
		valid bool
	}{
		{"valid", "iss", "https://accounts.google.com", true},
		{"legacy issuer", "iss", "accounts.google.com", true},
		{"wrong issuer", "iss", "https://attacker.example", false},
		{"missing issuer", "iss", "", false},
		{"wrong audience", "aud", "another-client", false},
		{"missing audience", "aud", nil, false},
		{"multiple audiences without azp", "aud", []string{"g-client-id", "other"}, false},
		{"wrong azp", "azp", "other", false},
		{"expired", "exp", int64(1), false},
		{"missing expiry", "exp", int64(0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"sub": "s", "iss": "https://accounts.google.com", "aud": "g-client-id", "exp": time.Now().Add(time.Hour).Unix()}
			claims[tc.field] = tc.value
			_, err := p.parseIDToken(signer.sign(t, claims))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
	// A valid signature cannot compensate for a mismatched transaction nonce.
	token := signer.sign(t, map[string]any{"sub": "s", "iss": "https://accounts.google.com", "aud": "g-client-id", "exp": time.Now().Add(time.Hour).Unix(), "nonce": GoogleNonce("original")})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"id_token": token})
	}))
	defer srv.Close()
	p.cfg.TokenURI = srv.URL
	for _, state := range []string{"", "other", "original"} {
		ident, err := p.Exchange(WithGoogleState(context.Background(), state), "code", "https://app.example.com")
		if state == "original" {
			if err != nil || ident == nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "nonce") {
			t.Fatal("nonce mismatch accepted")
		}
	}
}

func TestGoogleExchangeRejectsMissingIDToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at"}`))
	}))
	defer srv.Close()
	cfg := goldGoogleCfg()
	cfg.TokenURI = srv.URL
	p := NewGoogleProvider(cfg, srv.Client(), nil)
	if _, err := p.Exchange(context.Background(), "c", "https://app.example.com"); err == nil {
		t.Fatal("missing id_token must error")
	}
}

func TestGoogleHTTPClientDefaults(t *testing.T) {
	p := NewGoogleProvider(goldGoogleCfg(), nil, nil)
	if p.client == nil || p.client.Timeout != 10*time.Second {
		t.Fatal("default client must be 10s-timeout http.Client")
	}
}

func TestGoogleFailureReasonNeverEchoesUnknownErrors(t *testing.T) {
	if got := googleFailureReason(errors.New("authorization-code=private-code token=private-token")); got != "failed" {
		t.Fatalf("unexpected diagnostic category: %s", got)
	}
	if got := googleFailureReason(context.DeadlineExceeded); got != "timeout" {
		t.Fatal(got)
	}
}

package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// GOLDEN: the Google authorize URL must stay byte-identical (prompt=consent,
// no state — legacy webapps and the pairing chain depend on it).
func TestGoogleAuthURLGolden(t *testing.T) {
	p := NewGoogleProvider(goldGoogleCfg(), nil, nil)
	got := p.AuthURL("https://app.example.com", "ignored-state")
	want := "https://accounts.test/auth?client_id=g-client-id&prompt=consent&" +
		"redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth2%2Fcode%2Fgoogle&" +
		"response_type=code&scope=openid+email+profile"
	if got != want {
		t.Fatalf("authorize URL drifted:\n got %s\nwant %s", got, want)
	}
	if p.RequiresState() {
		t.Fatal("google must not require state (legacy wire)")
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
	idToken := unsignedIDToken(t, map[string]any{
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
	p := NewGoogleProvider(cfg, srv.Client(), nil)

	ident, err := p.Exchange(context.Background(), "the-code", "https://app.example.com")
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

// GOLDEN: with verification enabled, a JWKS failure degrades to parse-only
// instead of failing login (deployed semantics — do not "fix").
func TestGoogleVerificationDegradesWhenJWKSUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"` + unsignedIDToken(t, map[string]any{"sub": "s"}) + `"}`))
	}))
	defer srv.Close()
	cfg := goldGoogleCfg()
	cfg.TokenURI = srv.URL
	cfg.VerifyIDToken = true
	cfg.JWKSURI = "http://127.0.0.1:0/certs" // unreachable
	p := NewGoogleProvider(cfg, srv.Client(), nil)

	ident, err := p.Exchange(context.Background(), "c", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange must degrade, not fail: %v", err)
	}
	if ident.ProviderUserID != "s" {
		t.Fatalf("degraded parse must still yield claims, got %+v", ident)
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

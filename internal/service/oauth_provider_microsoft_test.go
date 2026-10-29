package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- shared helpers: mint RS256 id_tokens and serve a matching JWKS ---

type testSigner struct {
	key *rsa.PrivateKey
	kid string
}

func newTestRSAKey(t *testing.T) *testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{key: key, kid: "test-kid"}
}

func (s *testSigner) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": s.kid})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer serves the signer's public key.
func (s *testSigner) jwksServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pub := s.key.PublicKey
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[{"kid":%q,"kty":"RSA","n":%q,"e":%q}]}`,
			s.kid,
			base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()))
	}))
}

// --- Microsoft ---

func msFixture(t *testing.T, claims map[string]any) (*microsoftProvider, *httptest.Server) {
	t.Helper()
	signer := newTestRSAKey(t)
	jwks := signer.jwksServer(t)
	idToken := signer.sign(t, claims)
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"at","id_token":%q}`, idToken)
	}))
	t.Cleanup(tokenSrv.Close)
	t.Cleanup(jwks.Close)
	cfg := MicrosoftProviderConfig{
		ClientID:     "ms-client",
		ClientSecret: "ms-secret",
		RedirectURI:  "{baseUrl}/oauth2/code/microsoft",
		Tenant:       "common",
		TokenURI:     tokenSrv.URL,
		JWKSURI:      jwks.URL,
	}
	return NewMicrosoftProvider(cfg, tokenSrv.Client(), nil), tokenSrv
}

func msClaims() map[string]any {
	return map[string]any{
		"sub":            "ms-sub-1",
		"email":          "u@outlook.com",
		"email_verified": true,
		"name":           "User Name",
		"aud":            "ms-client",
		"iss":            "https://login.microsoftonline.com/9188040d-xxxx-xxxx/v2.0",
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func TestMicrosoftExchangeHappyPath(t *testing.T) {
	p, _ := msFixture(t, msClaims())
	ident, err := p.Exchange(context.Background(), "c", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ident.ProviderUserID != "ms-sub-1" || ident.Email != "u@outlook.com" ||
		!ident.EmailVerified || ident.DisplayName != "User Name" || ident.AvatarURL != "" {
		t.Fatalf("identity mapping: %+v", ident)
	}
	if ident.RawIDToken != "" {
		t.Fatal("microsoft must not populate RawIDToken (google-only double-write)")
	}
	if !p.RequiresState() {
		t.Fatal("microsoft must require state")
	}
}

func TestMicrosoftAuthURLCarriesState(t *testing.T) {
	p, _ := msFixture(t, msClaims())
	got := p.AuthURL("https://app.example.com", "st-ate")
	for _, want := range []string{
		"state=st-ate",
		"response_type=code",
		"redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth2%2Fcode%2Fmicrosoft",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize URL %q missing %q", got, want)
		}
	}
}

func TestMicrosoftRejectsBadClaims(t *testing.T) {
	cases := map[string]func() map[string]any{
		"iss mismatch": func() map[string]any {
			c := msClaims()
			c["iss"] = "https://evil.example.com/tenant/v2.0"
			return c
		},
		"iss wrong suffix": func() map[string]any {
			c := msClaims()
			c["iss"] = "https://login.microsoftonline.com/tenant/v1.0"
			return c
		},
		"aud mismatch": func() map[string]any {
			c := msClaims()
			c["aud"] = "other-app"
			return c
		},
		"expired": func() map[string]any {
			c := msClaims()
			c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
			return c
		},
		"missing sub": func() map[string]any {
			c := msClaims()
			delete(c, "sub")
			return c
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := msFixture(t, mutate())
			if _, err := p.Exchange(context.Background(), "c", "https://app.example.com"); err == nil {
				t.Fatal("must reject")
			}
		})
	}
}

// Strict policy: unlike Google, a broken signature must FAIL the exchange.
func TestMicrosoftRejectsBadSignature(t *testing.T) {
	signer := newTestRSAKey(t)
	jwks := signer.jwksServer(t)
	defer jwks.Close()
	other := newTestRSAKey(t) // signs with a key the JWKS never serves
	idToken := other.sign(t, msClaims())
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id_token":%q}`, idToken)
	}))
	defer tokenSrv.Close()
	p := NewMicrosoftProvider(MicrosoftProviderConfig{
		ClientID: "ms-client", TokenURI: tokenSrv.URL, JWKSURI: jwks.URL,
	}, tokenSrv.Client(), nil)
	if _, err := p.Exchange(context.Background(), "c", "https://app.example.com"); err == nil {
		t.Fatal("signature failure must be fatal for microsoft (no degradation)")
	}
}

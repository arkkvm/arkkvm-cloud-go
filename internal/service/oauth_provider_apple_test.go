package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Apple: p8 key minting and ES256 client-JWT verification helpers ---

func newTestP8(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return key, p8
}

// verifyTestES256 checks a JWS against the key and returns its claims.
func verifyTestES256(t *testing.T, token string, key *ecdsa.PrivateKey) (header map[string]string, claims map[string]any) {
	t.Helper()
	parts := splitJWS(token)
	if len(parts) != 3 {
		t.Fatal("client_secret is not a JWS")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		t.Fatal(err)
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("ES256 signature must be 64 octets, got %d", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("client_secret signature does not verify")
	}
	return header, claims
}

func appleFixture(t *testing.T, p8 string, claims map[string]any) (*appleProvider, *httptest.Server, *[]string) {
	t.Helper()
	signer := newTestRSAKey(t)
	jwks := signer.jwksServer(t)
	idToken := signer.sign(t, claims)
	var secrets []string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		secrets = append(secrets, r.PostFormValue("client_secret"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"at","id_token":%q}`, idToken)
	}))
	t.Cleanup(tokenSrv.Close)
	t.Cleanup(jwks.Close)
	cfg := AppleProviderConfig{
		ClientID:    "com.example.signin",
		TeamID:      "TEAM1234",
		KeyID:       "KEY1234",
		PrivateKey:  p8,
		RedirectURI: "{baseUrl}/oauth2/code/apple",
		TokenURI:    tokenSrv.URL,
		JWKSURI:     jwks.URL,
	}
	return NewAppleProvider(cfg, tokenSrv.Client(), nil), tokenSrv, &secrets
}

func appleClaims() map[string]any {
	return map[string]any{
		"sub":            "apple-sub-1",
		"email":          "user@privaterelay.appleid.com",
		"email_verified": "true", // Apple sends a string here
		"aud":            "com.example.signin",
		"iss":            "https://appleid.apple.com",
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func TestAppleExchangeHappyPath(t *testing.T) {
	_, p8 := newTestP8(t)
	p, _, _ := appleFixture(t, p8, appleClaims())

	ctx := WithCallbackUser(context.Background(),
		`{"name":{"firstName":"Jane","lastName":"Doe"},"email":"user@privaterelay.appleid.com"}`)
	ident, err := p.Exchange(ctx, "c", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ident.ProviderUserID != "apple-sub-1" {
		t.Fatalf("sub: %q", ident.ProviderUserID)
	}
	if ident.Email != "user@privaterelay.appleid.com" || !ident.EmailVerified {
		t.Fatalf("email mapping: %+v", ident)
	}
	// name arrives only via the callback form field
	if ident.DisplayName != "Jane Doe" {
		t.Fatalf("display name: %q", ident.DisplayName)
	}
	if ident.AvatarURL != "" || ident.RawIDToken != "" {
		t.Fatalf("apple must not populate avatar/RawIDToken: %+v", ident)
	}
}

func TestAppleExchangeWithoutUserField(t *testing.T) {
	_, p8 := newTestP8(t)
	p, _, _ := appleFixture(t, p8, appleClaims())
	ident, err := p.Exchange(context.Background(), "c", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ident.DisplayName != "" {
		t.Fatalf("no user field means no display name, got %q", ident.DisplayName)
	}
}

func TestAppleProfileFieldState(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"", "absent"}, {"null", "null"}, {`""`, "empty"},
		{`"  "`, "empty"}, {`"user@example.com"`, "present"},
		{`false`, "non_string"}, {`{}`, "non_string"},
	} {
		if got := appleProfileFieldState(json.RawMessage(tc.raw)); got != tc.want {
			t.Fatalf("field state = %s, want %s", got, tc.want)
		}
	}
}

func TestAppleExchangeMissingEmailDoesNotInventProfile(t *testing.T) {
	_, p8 := newTestP8(t)
	claims := appleClaims()
	delete(claims, "email")
	p, _, _ := appleFixture(t, p8, claims)
	ident, err := p.Exchange(context.Background(), "c", "https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ident.Email != "" || ident.DisplayName != "" || ident.ProviderUserID != "apple-sub-1" {
		t.Fatal("missing profile must not change identity or invent data")
	}
}

// The client_secret sent to Apple must be an ES256 client JWT minted from
// the p8 key: kid = key id, iss = team id, sub = Services ID, aud = issuer.
func TestAppleClientSecretIsSignedClientJWT(t *testing.T) {
	key, p8 := newTestP8(t)
	p, _, secrets := appleFixture(t, p8, appleClaims())

	if _, err := p.Exchange(context.Background(), "c", "https://app.example.com"); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(*secrets) != 1 {
		t.Fatalf("expected one token call, got %d", len(*secrets))
	}
	header, claims := verifyTestES256(t, (*secrets)[0], key)
	if header["alg"] != "ES256" || header["kid"] != "KEY1234" {
		t.Fatalf("client JWT header: %v", header)
	}
	if claims["iss"] != "TEAM1234" || claims["sub"] != "com.example.signin" ||
		claims["aud"] != "https://appleid.apple.com" {
		t.Fatalf("client JWT claims: %v", claims)
	}
	now := time.Now().Unix()
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if iat > now+5 || exp <= iat {
		t.Fatalf("client JWT lifetime: iat=%d exp=%d now=%d", iat, exp, now)
	}

	// Second exchange must reuse the cached secret (same JWT, no re-mint).
	if _, err := p.Exchange(context.Background(), "c2", "https://app.example.com"); err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if len(*secrets) != 2 || (*secrets)[1] != (*secrets)[0] {
		t.Fatal("client secret must be cached across exchanges")
	}
}

func TestAppleAuthURLFormPost(t *testing.T) {
	_, p8 := newTestP8(t)
	p, _, _ := appleFixture(t, p8, appleClaims())
	got := p.AuthURL("https://app.example.com", "st-ate")
	for _, want := range []string{
		"response_mode=form_post",
		"response_type=code",
		"scope=name+email",
		"state=st-ate",
		"redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth2%2Fcode%2Fapple",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize URL %q missing %q", got, want)
		}
	}
}

func TestAppleRejectsBadClaims(t *testing.T) {
	cases := map[string]func() map[string]any{
		"iss mismatch": func() map[string]any {
			c := appleClaims()
			c["iss"] = "https://evil.example.com"
			return c
		},
		"aud mismatch": func() map[string]any {
			c := appleClaims()
			c["aud"] = "other-services-id"
			return c
		},
		"expired": func() map[string]any {
			c := appleClaims()
			c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
			return c
		},
		"missing sub": func() map[string]any {
			c := appleClaims()
			delete(c, "sub")
			return c
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, p8 := newTestP8(t)
			p, _, _ := appleFixture(t, p8, mutate())
			if _, err := p.Exchange(context.Background(), "c", "https://app.example.com"); err == nil {
				t.Fatal("must reject")
			}
		})
	}
}

// Strict policy: a broken signature must FAIL the exchange.
func TestAppleRejectsBadSignature(t *testing.T) {
	_, p8 := newTestP8(t)
	signer := newTestRSAKey(t)
	jwks := signer.jwksServer(t)
	defer jwks.Close()
	other := newTestRSAKey(t) // signs with a key the JWKS never serves
	idToken := other.sign(t, appleClaims())
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id_token":%q}`, idToken)
	}))
	defer tokenSrv.Close()
	p := NewAppleProvider(AppleProviderConfig{
		ClientID: "com.example.signin", TeamID: "T", KeyID: "K", PrivateKey: p8,
		TokenURI: tokenSrv.URL, JWKSURI: jwks.URL,
	}, tokenSrv.Client(), nil)
	if _, err := p.Exchange(context.Background(), "c", "https://app.example.com"); err == nil {
		t.Fatal("signature failure must be fatal for apple")
	}
}

func TestApplePrivateKeyVariants(t *testing.T) {
	_, p8 := newTestP8(t)

	// \n-escaped PEM (env files flatten newlines).
	escaped := NewAppleProvider(AppleProviderConfig{
		ClientID: "c", TeamID: "T", KeyID: "K", PrivateKey: strings.ReplaceAll(p8, "\n", "\\n"),
	}, nil, nil)
	if _, err := escaped.clientSecret(); err != nil {
		t.Fatalf("escaped PEM: %v", err)
	}

	// File path.
	path := filepath.Join(t.TempDir(), "AuthKey_TEST.p8")
	if err := os.WriteFile(path, []byte(p8), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile := NewAppleProvider(AppleProviderConfig{
		ClientID: "c", TeamID: "T", KeyID: "K", PrivateKey: path,
	}, nil, nil)
	if _, err := fromFile.clientSecret(); err != nil {
		t.Fatalf("file path: %v", err)
	}

	// Garbage must fail loudly, not panic.
	broken := NewAppleProvider(AppleProviderConfig{
		ClientID: "c", TeamID: "T", KeyID: "K", PrivateKey: "not-a-key",
	}, nil, nil)
	if _, err := broken.clientSecret(); err == nil {
		t.Fatal("garbage key material must fail")
	}

	// An RSA p8 must be rejected (ES256 needs EC P-256).
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	rsaP8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	wrongType := NewAppleProvider(AppleProviderConfig{
		ClientID: "c", TeamID: "T", KeyID: "K", PrivateKey: rsaP8,
	}, nil, nil)
	if _, err := wrongType.clientSecret(); err == nil {
		t.Fatal("RSA key material must be rejected")
	}
}

func TestAppleNameFromUserFormatting(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"han", `{"name":{"firstName":"\u660e","lastName":"\u738b"}}`, "\u738b\u660e"},
		{"compound family", `{"name":{"firstName":"\u660e","lastName":"\u6b27\u9633"}}`, "\u6b27\u9633\u660e"},
		{"latin", `{"name":{"firstName":" Jane ","lastName":" Doe "}}`, "Jane Doe"},
		{"mixed", `{"name":{"firstName":"Jane","lastName":"\u738b"}}`, "Jane \u738b"},
		{"given only", `{"name":{"firstName":"\u660e"}}`, "\u660e"},
		{"family only", `{"name":{"lastName":"\u738b"}}`, "\u738b"},
		{"empty", `{}`, ""},
		{"invalid", `broken`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := appleNameFromUser(tc.raw); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

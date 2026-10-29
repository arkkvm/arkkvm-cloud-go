package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

// callbackUserKey carries the raw callback form field `user` through the
// request context. Sign in with Apple delivers the profile (name, email)
// on the user's first authorization as a form_post field. The name is not
// included in the id_token; email can also be obtained from that token.
// The handler stashes it; Apple is currently the only
// consumer, everything else ignores it.
type callbackUserKey struct{}

// WithCallbackUser stashes the raw `user` form field of an OAuth callback
// into the request context (no-op when empty).
func WithCallbackUser(ctx context.Context, raw string) context.Context {
	if raw == "" {
		return ctx
	}
	return context.WithValue(ctx, callbackUserKey{}, raw)
}

func callbackUser(ctx context.Context) string {
	v, _ := ctx.Value(callbackUserKey{}).(string)
	return v
}

// appleProvider implements Sign in with Apple (OAuth2/OIDC hybrid). Two
// quirks set it apart from the other providers:
//
//   - The client_secret is not a static string but an ES256-signed client
//     JWT minted from the p8 team key (kid = key id, iss = team id,
//     sub = Services ID). Apple caps its lifetime at ~6 months; we mint on
//     demand and refresh after 150 days.
//   - The authorization response arrives via response_mode=form_post: Apple
//     POSTs code+state to the redirect URI. The callback handler must read
//     the form body (router registers the POST verb for this).
//
// Verification is strict — RS256 against Apple's JWKS, exact iss, aud ==
// Services ID, exp — failures are fatal (no legacy parity to preserve).
type appleProvider struct {
	cfg    AppleProviderConfig
	client *http.Client
	jwks   *jwksCache

	mu          sync.Mutex
	key         *ecdsa.PrivateKey
	secretToken string
	secretExp   time.Time
}

// AppleProviderConfig mirrors the oauth2.apple config block.
type AppleProviderConfig struct {
	ClientID    string // Apple Services ID (the OAuth client_id)
	TeamID      string // Apple Developer Team ID (client JWT iss)
	KeyID       string // p8 key id (client JWT kid)
	PrivateKey  string // p8 contents (PEM, \n-escaped PEM, or a file path)
	RedirectURI string // template containing {baseUrl}
	Scope       string
	AuthURI     string
	TokenURI    string
	JWKSURI     string
}

const appleIssuer = "https://appleid.apple.com"

// Apple caps the client-secret lifetime at 15777000s (~182.6 days); refresh
// well before that.
const appleSecretTTL = 150 * 24 * time.Hour

func NewAppleProvider(cfg AppleProviderConfig, client *http.Client, jwks *jwksCache) *appleProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if jwks == nil {
		jwks = NewJWKSCache(client)
	}
	if cfg.Scope == "" {
		cfg.Scope = "name email"
	}
	if cfg.AuthURI == "" {
		cfg.AuthURI = appleIssuer + "/auth/authorize"
	}
	if cfg.TokenURI == "" {
		cfg.TokenURI = appleIssuer + "/auth/token"
	}
	if cfg.JWKSURI == "" {
		cfg.JWKSURI = appleIssuer + "/auth/keys"
	}
	return &appleProvider{cfg: cfg, client: client, jwks: jwks}
}

func (p *appleProvider) Name() string        { return "apple" }
func (p *appleProvider) RequiresState() bool { return true }

// AuthURL builds the Apple consent URL. response_mode=form_post is required
// whenever scope carries name/email: Apple then POSTs the authorization
// response to the redirect URI instead of a query-string redirect.
func (p *appleProvider) AuthURL(baseURL, state string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	q.Set("response_type", "code")
	q.Set("scope", p.cfg.Scope)
	q.Set("response_mode", "form_post")
	q.Set("state", state)
	return p.cfg.AuthURI + "?" + q.Encode()
}

type appleIDClaims struct {
	Sub            string    `json:"sub"`
	Email          string    `json:"email"`
	EmailVerified  appleBool `json:"email_verified"`
	IsPrivateEmail appleBool `json:"is_private_email"`
	Aud            string    `json:"aud"`
	Iss            string    `json:"iss"`
	Exp            int64     `json:"exp"`
}

// appleBool accepts true/false as JSON bool or string — Apple documents
// email_verified / is_private_email as "String or Boolean".
type appleBool bool

func (b *appleBool) UnmarshalJSON(v []byte) error {
	switch s := strings.Trim(string(v), `"`); s {
	case "true":
		*b = true
	case "false", "null", "":
		*b = false
	default:
		return fmt.Errorf("invalid boolean %q", s)
	}
	return nil
}

// Exchange swaps the code for the Apple identity: mint the client JWT, hit
// the token endpoint, then verify the id_token (signature, iss, aud, exp).
func (p *appleProvider) Exchange(ctx context.Context, code, baseURL string) (*Identity, error) {
	secret, err := p.clientSecret()
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", secret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}
	if tokens.IDToken == "" {
		return nil, errors.New("token endpoint returned no id_token")
	}

	var claims appleIDClaims
	if err := jwsClaims(tokens.IDToken, &claims); err != nil {
		return nil, err
	}
	if claims.Sub == "" {
		return nil, errors.New("id_token has no sub")
	}
	if claims.Iss != appleIssuer {
		return nil, fmt.Errorf("id_token iss mismatch: %q", claims.Iss)
	}
	if claims.Aud != p.cfg.ClientID {
		return nil, fmt.Errorf("id_token aud mismatch")
	}
	// 60s clock-skew tolerance.
	if claims.Exp > 0 && time.Now().After(time.Unix(claims.Exp+60, 0)) {
		return nil, errors.New("id_token expired")
	}
	if err := verifyRS256Signature(p.jwks, tokens.IDToken, p.cfg.JWKSURI); err != nil {
		return nil, fmt.Errorf("id_token signature verification failed: %w", err)
	}
	// Inspect only validated claims and only log presence/type, never values.
	// This distinguishes provider omissions from profile mapping mistakes.
	var rawClaims map[string]json.RawMessage
	if err := jwsClaims(tokens.IDToken, &rawClaims); err != nil {
		return nil, err
	}
	slog.Info("apple token profile inspected",
		"email_claim_state", appleProfileFieldState(rawClaims["email"]),
		"name_claim_state", appleProfileFieldState(rawClaims["name"]),
		"parsed_email_present", strings.TrimSpace(claims.Email) != "",
		"callback_user_present", strings.TrimSpace(callbackUser(ctx)) != "",
		"parsed_name_present", appleNameFromUser(callbackUser(ctx)) != "")

	// The user's name (if shared) rides only the first-authorization form
	// field, never the id_token. Email prefers the signed id_token claim.
	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		EmailVerified:  bool(claims.EmailVerified),
		DisplayName:    appleNameFromUser(callbackUser(ctx)),
		// no avatar: Apple never supplies one.
	}, nil
}

func appleProfileFieldState(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "absent"
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return "null"
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "non_string"
	}
	if strings.TrimSpace(value) == "" {
		return "empty"
	}
	return "present"
}

type appleFormUser struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
}

func appleNameFromUser(raw string) string {
	if raw == "" {
		return ""
	}
	var u appleFormUser
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		return ""
	}
	first := strings.TrimSpace(u.Name.FirstName)
	last := strings.TrimSpace(u.Name.LastName)
	// Use family-name-first formatting for entirely Han-script components.
	// The web callback has no locale; retain given-name-first formatting for
	// other scripts and mixed names rather than guessing their convention.
	allHan := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			if !unicode.Is(unicode.Han, r) {
				return false
			}
		}
		return true
	}
	if allHan(first) && allHan(last) {
		return last + first
	}
	return strings.TrimSpace(first + " " + last)
}

// clientSecret mints (and caches) the ES256 client JWT Apple requires in
// place of a static client_secret. Claims per https://appleid.apple.com:
// iss = Team ID, iat/exp, aud = Apple's issuer, sub = Services ID.
func (p *appleProvider) clientSecret() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.key == nil {
		key, err := parseApplePrivateKey(p.cfg.PrivateKey)
		if err != nil {
			return "", err
		}
		p.key = key
	}
	if p.secretToken != "" && now.Before(p.secretExp) {
		return p.secretToken, nil
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": p.cfg.KeyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": p.cfg.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(appleSecretTTL).Unix(),
		"aud": appleIssuer,
		"sub": p.cfg.ClientID,
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, digest[:])
	if err != nil {
		return "", err
	}
	// JWS ES256 signature is the fixed-width r||s octet pair, not DER.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	p.secretToken = signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	p.secretExp = now.Add(appleSecretTTL)
	return p.secretToken, nil
}

// parseApplePrivateKey loads the p8 team key from raw PEM, \n-escaped PEM
// (multiline secrets arrive flattened through env files), or a file path.
func parseApplePrivateKey(raw string) (*ecdsa.PrivateKey, error) {
	// A flattened PEM has no real newlines left, only literal "\n" — unescape
	// before anything else (a path never contains that sequence).
	if !strings.Contains(raw, "\n") {
		raw = strings.ReplaceAll(raw, "\\n", "\n")
	}
	if !strings.Contains(raw, "-----BEGIN") {
		if data, err := os.ReadFile(raw); err == nil {
			raw = string(data)
		}
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("apple private key: no PEM block found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apple private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apple private key must be an EC P-256 PKCS#8 (p8) key")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("apple private key curve must be P-256")
	}
	return key, nil
}

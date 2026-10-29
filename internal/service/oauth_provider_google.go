package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// googleProvider carries the legacy OAuthService logic unchanged (:
// "Move Google logic into googleProvider without changing wire behavior"). Profile claims
// include the optional name, but the golden tests still lock the authorize
// URL, token form and callback query. The silent-degradation behavior and
// state-less authorize URL remain legacy contracts for webapps and pairing.
type googleProvider struct {
	cfg    GoogleProviderConfig
	client *http.Client
	jwks   *jwksCache
}

// GoogleProviderConfig mirrors the oauth2.google config block.
type GoogleProviderConfig struct {
	ClientID      string
	ClientSecret  string
	RedirectURI   string // template containing {baseUrl}
	Scope         string
	AuthURI       string
	TokenURI      string
	JWKSURI       string
	VerifyIDToken bool
}

func NewGoogleProvider(cfg GoogleProviderConfig, client *http.Client, jwks *jwksCache) *googleProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if jwks == nil {
		jwks = NewJWKSCache(client)
	}
	return &googleProvider{cfg: cfg, client: client, jwks: jwks}
}

func (p *googleProvider) Name() string        { return "google" }
func (p *googleProvider) RequiresState() bool { return false }

// googleIDClaims carries the identity fields consumed by upsert; email_verified
// is parsed additionally for the (provider-internal) verified flag.
type googleIDClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// AuthURL builds the Google consent page URL for the given base URL
// (scheme://host[:port] of the incoming request). state is ignored: the
// legacy flow never carried one and must keep that shape.
func (p *googleProvider) AuthURL(baseURL, state string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	q.Set("response_type", "code")
	q.Set("scope", p.cfg.Scope)
	q.Set("prompt", "consent")
	return p.cfg.AuthURI + "?" + q.Encode()
}

// Exchange swaps the authorization code for the Google identity. Mirrors the
// legacy chain exactly: form-POST token exchange, then id_token parsing with
// optional RS256 verification that degrades to parse-only when verification
// fails (deployed semantics — JWKS unreachability must not break login).
func (p *googleProvider) Exchange(ctx context.Context, code, baseURL string) (*Identity, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	form.Set("grant_type", "authorization_code")

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
	claims, err := p.parseIDToken(tokens.IDToken)
	if err != nil || claims.Sub == "" {
		if err == nil {
			err = errors.New("id_token has no sub")
		}
		return nil, err
	}
	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		DisplayName:    claims.Name,
		AvatarURL:      claims.Picture,
		RawIDToken:     tokens.IDToken,
	}, nil
}

// parseIDToken extracts the claims. When verification is enabled the RS256
// signature is checked against the JWKS; a verification failure degrades to
// parse-only (matching the trust model of the token-endpoint TLS response).
func (p *googleProvider) parseIDToken(idToken string) (*googleIDClaims, error) {
	var claims googleIDClaims
	if err := jwsClaims(idToken, &claims); err != nil {
		return nil, err
	}
	if p.cfg.VerifyIDToken {
		if err := verifyRS256Signature(p.jwks, idToken, p.cfg.JWKSURI); err != nil {
			return &claims, nil // degraded: claims parsed, signature unverified
		}
	}
	return &claims, nil
}

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

// microsoftProvider implements the Microsoft Entra ID v2.0 OIDC code flow
// (tenant configurable, default "common" = consumer + work accounts).
// Unlike Google this provider REJECTS on any verification failure — no
// legacy parity to preserve, so the strictest rules apply.
type microsoftProvider struct {
	cfg    MicrosoftProviderConfig
	client *http.Client
	jwks   *jwksCache
}

// MicrosoftProviderConfig mirrors the oauth2.microsoft config block.
type MicrosoftProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string // template containing {baseUrl}
	Scope        string
	Tenant       string // default common; iss only prefix/suffix-checked
	AuthURI      string
	TokenURI     string
	JWKSURI      string
}

func NewMicrosoftProvider(cfg MicrosoftProviderConfig, client *http.Client, jwks *jwksCache) *microsoftProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if jwks == nil {
		jwks = NewJWKSCache(client)
	}
	if cfg.Tenant == "" {
		cfg.Tenant = "common"
	}
	if cfg.Scope == "" {
		cfg.Scope = "openid email profile"
	}
	if cfg.AuthURI == "" {
		cfg.AuthURI = "https://login.microsoftonline.com/" + cfg.Tenant + "/oauth2/v2.0/authorize"
	}
	if cfg.TokenURI == "" {
		cfg.TokenURI = "https://login.microsoftonline.com/" + cfg.Tenant + "/oauth2/v2.0/token"
	}
	if cfg.JWKSURI == "" {
		cfg.JWKSURI = "https://login.microsoftonline.com/" + cfg.Tenant + "/discovery/v2.0/keys"
	}
	return &microsoftProvider{cfg: cfg, client: client, jwks: jwks}
}

func (p *microsoftProvider) Name() string        { return "microsoft" }
func (p *microsoftProvider) RequiresState() bool { return true }

type microsoftIDClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Aud           string `json:"aud"`
	Iss           string `json:"iss"`
	Exp           int64  `json:"exp"`
}

// AuthURL builds the Entra v2.0 consent URL. state is mandatory (validated
// at callback via the signed cookie).
func (p *microsoftProvider) AuthURL(baseURL, state string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	q.Set("response_type", "code")
	q.Set("scope", p.cfg.Scope)
	q.Set("state", state)
	return p.cfg.AuthURI + "?" + q.Encode()
}

// Exchange swaps the code for the Microsoft identity. The id_token must pass
// RS256 signature verification plus iss (tenant-prefixed, /v2.0-suffixed),
// aud and exp checks — failures are fatal.
func (p *microsoftProvider) Exchange(ctx context.Context, code, baseURL string) (*Identity, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	form.Set("grant_type", "authorization_code")
	form.Set("scope", p.cfg.Scope)

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

	var claims microsoftIDClaims
	if err := jwsClaims(tokens.IDToken, &claims); err != nil {
		return nil, err
	}
	if claims.Sub == "" {
		return nil, errors.New("id_token has no sub")
	}
	// iss is tenant-specific (home tenant when Tenant=common): only the
	// stable prefix/suffix shape is enforced.
	if !strings.HasPrefix(claims.Iss, "https://login.microsoftonline.com/") || !strings.HasSuffix(claims.Iss, "/v2.0") {
		return nil, fmt.Errorf("id_token iss mismatch: %q", claims.Iss)
	}
	if claims.Aud != p.cfg.ClientID {
		return nil, fmt.Errorf("id_token aud mismatch")
	}
	// 60s clock-skew tolerance.
	if claims.Exp > 0 && time.Now().After(time.Unix(claims.Exp+60, 0)) {
		return nil, errors.New("id_token expired")
	}
	// Strict: verification failure is fatal (no Google-style degradation).
	if err := verifyRS256Signature(p.jwks, tokens.IDToken, p.cfg.JWKSURI); err != nil {
		return nil, fmt.Errorf("id_token signature verification failed: %w", err)
	}

	return &Identity{
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		DisplayName:    claims.Name,
		// picture intentionally empty — fetching it would need a Graph call.
	}, nil
}

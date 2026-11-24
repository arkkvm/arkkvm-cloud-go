package service

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// googleProvider validates Google identities while preserving legacy pairing fields.
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
	VerifyIDToken bool // Deprecated: verification is always enforced.
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
func (p *googleProvider) RequiresState() bool { return true }

// googleIDClaims carries the identity fields consumed by upsert; email_verified
// is parsed additionally for the (provider-internal) verified flag.
type googleIDClaims struct {
	Sub           string          `json:"sub"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	Name          string          `json:"name"`
	Picture       string          `json:"picture"`
	Iss           string          `json:"iss"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	Exp           int64           `json:"exp"`
	Nonce         string          `json:"nonce"`
}

// AuthURL binds the authorization response to the initiating browser.
func (p *googleProvider) AuthURL(baseURL, state string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	q.Set("response_type", "code")
	q.Set("scope", p.cfg.Scope)
	q.Set("prompt", "consent")
	q.Set("state", state)
	q.Set("nonce", GoogleNonce(state))
	return p.cfg.AuthURI + "?" + q.Encode()
}

// Exchange rejects invalid signatures, claims and transaction nonces.
func (p *googleProvider) Exchange(ctx context.Context, code, baseURL string) (_ *Identity, exchangeErr error) {
	stage, upstreamError, upstreamStatus := "request", "", 0
	defer func() {
		if exchangeErr != nil {
			// Log only fixed diagnostic categories. Never log provider payloads,
			// authorization codes, credentials, token claims or arbitrary error text.
			slog.Warn("google identity exchange failed", "stage", stage,
				"reason", googleFailureReason(exchangeErr), "upstream_status", upstreamStatus,
				"upstream_error", upstreamError, "error_type", fmt.Sprintf("%T", exchangeErr))
		}
	}()
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

	stage = "token_transport"
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	stage = "token_response"
	upstreamStatus = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure)
		switch failure.Error {
		case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "temporarily_unavailable":
			upstreamError = failure.Error
		default:
			upstreamError = "unclassified"
		}
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	stage = "token_decode"
	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}
	if tokens.IDToken == "" {
		return nil, errors.New("token endpoint returned no id_token")
	}
	stage = "id_token_validation"
	claims, err := p.parseIDToken(tokens.IDToken)
	if err != nil || claims.Sub == "" {
		if err == nil {
			err = errors.New("id_token has no sub")
		}
		return nil, err
	}
	stage = "nonce_validation"
	expected, _ := ctx.Value(googleStateKey{}).(string)
	if expected == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(GoogleNonce(expected))) != 1 {
		return nil, errors.New("id_token nonce mismatch")
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

// GoogleNonce derives a separate OIDC nonce from the random OAuth state.
func GoogleNonce(state string) string {
	sum := sha256.Sum256([]byte("arkkvm-google-nonce:" + state))
	return hex.EncodeToString(sum[:])
}

type googleStateKey struct{}

func WithGoogleState(ctx context.Context, state string) context.Context {
	return context.WithValue(ctx, googleStateKey{}, state)
}

// parseIDToken always fails closed, including if a legacy configuration
// attempts to disable verification. VerifyIDToken is retained for config compatibility.
func (p *googleProvider) parseIDToken(idToken string) (*googleIDClaims, error) {
	if err := verifyRS256Signature(p.jwks, idToken, p.cfg.JWKSURI); err != nil {
		return nil, fmt.Errorf("id_token signature verification failed: %w", err)
	}
	var claims googleIDClaims
	if err := jwsClaims(idToken, &claims); err != nil {
		return nil, err
	}
	if claims.Iss != "https://accounts.google.com" && claims.Iss != "accounts.google.com" {
		return nil, errors.New("id_token issuer mismatch")
	}
	var audiences []string
	var audience string
	if err := json.Unmarshal(claims.Aud, &audience); err == nil {
		audiences = []string{audience}
	} else if err := json.Unmarshal(claims.Aud, &audiences); err != nil {
		return nil, errors.New("id_token audience missing or invalid")
	}
	matched := false
	for _, aud := range audiences {
		if aud == p.cfg.ClientID && aud != "" {
			matched = true
		}
	}
	if !matched || (len(audiences) > 1 && claims.Azp != p.cfg.ClientID) || (claims.Azp != "" && claims.Azp != p.cfg.ClientID) {
		return nil, errors.New("id_token audience mismatch")
	}
	if claims.Exp <= 0 || claims.Exp < time.Now().Unix()-60 {
		return nil, errors.New("id_token expired or missing expiry")
	}
	return &claims, nil
}

// googleFailureReason returns fixed categories, never the original error text.
func googleFailureReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	switch err.Error() {
	case "id_token nonce mismatch":
		return "nonce_mismatch"
	case "id_token issuer mismatch":
		return "issuer_mismatch"
	case "id_token audience mismatch", "id_token audience missing or invalid":
		return "audience_mismatch"
	case "id_token expired or missing expiry":
		return "expiry_invalid"
	case "id_token has no sub":
		return "subject_missing"
	case "token endpoint returned no id_token":
		return "id_token_missing"
	}
	if strings.HasPrefix(err.Error(), "id_token signature verification failed:") {
		var requestError *url.Error
		var syntaxError *json.SyntaxError
		switch {
		case errors.As(err, &requestError):
			return "jwks_transport_failure"
		case errors.Is(err, rsa.ErrVerification):
			return "signature_mismatch"
		case errors.As(err, &syntaxError):
			return "jwks_json_invalid"
		case strings.Contains(err.Error(), "not found in JWKS"):
			return "signing_key_missing"
		case strings.Contains(err.Error(), "jwks endpoint returned"):
			return "jwks_http_failure"
		case strings.Contains(err.Error(), "unexpected id_token alg"):
			return "signature_algorithm_invalid"
		}
		return "signature_or_jwks_failure"
	}
	return "failed"
}

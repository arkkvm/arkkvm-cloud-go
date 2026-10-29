// Package service — OAuth provider abstraction.
//
// Every provider implements the authorization-code flow behind one interface:
// build the consent URL, then swap the callback code for a normalized
// Identity. The handler layer owns sessions/cookies/redirects and never sees
// provider-specific wire formats.
package service

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// OAuthProvider is one configured login provider. Implementations must be
// safe for concurrent use.
type OAuthProvider interface {
	// Name is the URL slug: POST /oidc/{name} and GET /oauth2/code/{name}.
	Name() string

	// AuthURL builds the consent-page redirect for the request's base URL.
	// Providers that require CSRF state receive a non-empty state; Google
	// ignores it (its legacy flow never carried state — wire locked).
	AuthURL(baseURL, state string) string

	// Exchange swaps the authorization code for the provider identity
	// (server-to-server; the browser never sees tokens).
	Exchange(ctx context.Context, code, baseURL string) (*Identity, error)

	// RequiresState reports whether the authorization request must carry a
	// server-issued state (validated at callback). New providers: true.
	RequiresState() bool
}

// Identity is the provider-normalized login identity consumed by upsert.
type Identity struct {
	// ProviderUserID is the stable provider-scoped key: google/microsoft
	// OIDC sub, github numeric id, wechat unionid (fallback openid).
	ProviderUserID string
	Email          string
	EmailVerified  bool
	DisplayName    string
	AvatarURL      string
	// RawIDToken preserves the Google id_token for the legacy user.oidc_token
	// double-write (offer-frame compatibility); empty for non-OIDC providers.
	RawIDToken string
}

// tokenResponse is the OAuth2 token endpoint payload (only the fields used).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// jwsHeader is the JOSE header subset needed for RS256 verification.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// verifyRS256Signature checks the RS256 signature of a JWS against the JWKS
// at jwksURI. Shared by every OIDC provider; callers decide whether a
// failure is fatal (Microsoft rejects, Google degrades — legacy semantics).
func verifyRS256Signature(jwks *jwksCache, idToken, jwksURI string) error {
	parts := splitJWS(idToken)
	if len(parts) != 3 {
		return fmt.Errorf("malformed id_token")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var header jwsHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return err
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("unexpected id_token alg %q", header.Alg)
	}
	key, err := jwks.key(header.Kid, jwksURI)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig)
}

func splitJWS(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	return append(parts, token[start:])
}

// jwsClaims decodes the payload segment of a JWS into out.
func jwsClaims(token string, out any) error {
	parts := splitJWS(token)
	if len(parts) != 3 {
		return fmt.Errorf("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode id_token payload: %w", err)
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("parse id_token claims: %w", err)
	}
	return nil
}

// jwksCache caches rotating JWKS keys in memory, keyed by URI so several
// OIDC providers (Google, Microsoft) share one cache safely.
type jwksCache struct {
	mu      sync.Mutex
	client  *http.Client
	entries map[string]*jwksEntry
}

type jwksEntry struct {
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func NewJWKSCache(client *http.Client) *jwksCache {
	return &jwksCache{client: client, entries: map[string]*jwksEntry{}}
}

func (c *jwksCache) key(kid, jwksURI string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[jwksURI]
	if entry == nil || time.Since(entry.fetched) > time.Hour {
		if err := c.fetch(jwksURI); err != nil {
			return nil, err
		}
		entry = c.entries[jwksURI]
	}
	if k, ok := entry.keys[kid]; ok {
		return k, nil
	}
	// Unknown kid: refresh once (key rotation).
	if err := c.fetch(jwksURI); err != nil {
		return nil, err
	}
	if k, ok := c.entries[jwksURI].keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("kid %q not found in JWKS", kid)
}

func (c *jwksCache) fetch(jwksURI string) error {
	resp, err := c.client.Get(jwksURI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 + int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	c.entries[jwksURI] = &jwksEntry{keys: keys, fetched: time.Now()}
	return nil
}

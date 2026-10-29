package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// turnCredentialTTL matches the Cloudflare path's 3600s: coturn honours the
// credential's embedded expiry as the allocation ceiling.
const turnCredentialTTL = time.Hour

// TurnConfig selects the credential issuer for /webrtc/ice_config, in
// priority order:
//
//  1. Cloudflare (CloudflareKeyID set) — international deployments.
//  2. Self-hosted coturn REST credentials (SelfHostedSecret + URLs set) —
//     the CN posture: coturn runs with use-auth-secret and the same shared
//     secret; username = expiry unix seconds, credential =
//     base64(HMAC-SHA1(secret, username)).
//  3. Static STUN (StaticStun set, no credentials) — STUN-only fallback so
//     the console's connect flow (which gates its WebSocket on this
//     endpoint) stays alive.
//
// With nothing configured GenerateCredentials returns an error.
type TurnConfig struct {
	CloudflareKeyID    string
	CloudflareAPIToken string
	StaticStun         []string
	SelfHostedSecret   string
	SelfHostedTurnURLs []string
	Client             *http.Client
}

// TurnService issues the ICE configuration for /webrtc/ice_config. The
// "User-Agent: Application" header is mandatory on the Cloudflare path —
// Cloudflare rejects the call with 403 without it (confirmed by the legacy
// code and retested during migration).
type TurnService struct {
	cfg TurnConfig

	// CachedCredentials memoizes the issuer answer: the Cloudflare path costs
	// an API round trip per call, so the offer-frame path (one call per
	// offer) reuses the credential well inside its 3600s validity.
	mu        sync.Mutex
	cached    *ICEServer
	cachedExp time.Time
}

func NewTurnService(cfg TurnConfig) *TurnService {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 15 * time.Second}
	}
	return &TurnService{cfg: cfg}
}

// CachedCredentials returns GenerateCredentials' answer through a small
// 50-minute cache (credentials live 3600s; refresh well before expiry).
func (s *TurnService) CachedCredentials(ctx context.Context) (*ICEServer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.cached != nil && now.Before(s.cachedExp) {
		return s.cached, nil
	}
	ice, err := s.GenerateCredentials(ctx)
	if err != nil {
		return nil, err
	}
	s.cached = ice
	s.cachedExp = now.Add(50 * time.Minute)
	return ice, nil
}

// ICEServer is the single iceServers entry of the Cloudflare response.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type turnGenerateResponse struct {
	ICEServers ICEServer `json:"iceServers"`
}

// GenerateCredentials returns the ICE servers handed to WebRTC initiators.
func (s *TurnService) GenerateCredentials(ctx context.Context) (*ICEServer, error) {
	switch {
	case s.cfg.CloudflareKeyID != "":
		return s.cloudflareCredentials(ctx)
	case s.cfg.SelfHostedSecret != "" && len(s.cfg.SelfHostedTurnURLs) > 0:
		return s.selfHostedCredentials(), nil
	case len(s.cfg.StaticStun) > 0:
		return &ICEServer{URLs: append([]string(nil), s.cfg.StaticStun...)}, nil
	default:
		return nil, fmt.Errorf("no turn issuer configured (cloudflare key, self-hosted secret, or static stun)")
	}
}

func (s *TurnService) cloudflareCredentials(ctx context.Context) (*ICEServer, error) {
	endpoint := fmt.Sprintf(
		"https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate", s.cfg.CloudflareKeyID)

	body := strings.NewReader(`{"ttl":3600}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.CloudflareAPIToken)
	req.Header.Set("User-Agent", "Application")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Cloudflare answers 201 Created on success — accept the whole 2xx range
	// (checking == 200 rejected every successful call).
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("cloudflare turn api returned %d", resp.StatusCode)
	}
	var out turnGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	filtered := out.ICEServers.URLs[:0]
	for _, u := range out.ICEServers.URLs {
		if !strings.HasPrefix(u, "turns:") {
			filtered = append(filtered, u)
		}
	}
	out.ICEServers.URLs = filtered
	return &out.ICEServers, nil
}

// selfHostedCredentials mints coturn REST-API credentials: the username is
// the expiry unix timestamp and the password is base64(HMAC-SHA1(shared
// secret, username)) — the exact contract exercised against the deployed
// coturn with turnutils_uclient. The configured STUN entries ride along in
// front of the TURN urls, matching the Cloudflare response's stun+turn shape
// (TURN alone would also expose a reflexive address, but cheap STUN discovery
// first is the better-practice ordering).
func (s *TurnService) selfHostedCredentials() *ICEServer {
	expiry := time.Now().Add(turnCredentialTTL).Unix()
	username := strconv.FormatInt(expiry, 10)
	mac := hmac.New(sha1.New, []byte(s.cfg.SelfHostedSecret))
	mac.Write([]byte(username))
	urls := make([]string, 0, len(s.cfg.StaticStun)+len(s.cfg.SelfHostedTurnURLs))
	urls = append(urls, s.cfg.StaticStun...)
	urls = append(urls, s.cfg.SelfHostedTurnURLs...)
	return &ICEServer{
		URLs:       urls,
		Username:   username,
		Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	}
}

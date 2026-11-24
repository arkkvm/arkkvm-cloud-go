package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"arkkvm.com/arkkvm-cloud/internal/auth"
	"arkkvm.com/arkkvm-cloud/internal/model"
	"arkkvm.com/arkkvm-cloud/internal/pkg"
	"arkkvm.com/arkkvm-cloud/internal/service"
)

// oauthUsers / oauthDevices narrow the service dependencies so the callback
// contract (302 query shape) is golden-testable without a database.
// *service.UserService / *service.DeviceService implement them.
type oauthUsers interface {
	UpsertByIdentity(ctx context.Context, provider string, ident *service.Identity) (int64, error)
}

type oauthDevices interface {
	FindBySecretToken(ctx context.Context, secretToken string) (string, *string, error)
	GetByID(ctx context.Context, deviceID string) (*model.Device, error)
}

// OAuthHandler serves the provider OAuth2 flows (doc 14 §4): one shared
// authorize/callback pair per configured provider plus the device-local
// quick login. The Google branch preserves legacy
// pairing callback fields token/clientId/oidcGoogle/deviceId. Every
// provider requires state; Google additionally validates the OIDC nonce.
type OAuthHandler struct {
	providers map[string]service.OAuthProvider
	order     []string // registration order, stable for the providers endpoint

	users   oauthUsers
	devices oauthDevices
	tokens  *auth.TokenService
	cookies *auth.CookieManager

	trustProxyHeaders       bool
	trustedProxies          *pkg.TrustedProxies
	quickLoginRequireSecret bool
	clientID                string // legacy callback parameter (google only)
	// Phase-C gate (doc 14 §7C): stop clientId/oidcGoogle on google pairing
	// redirects when the device's cloud_version >= this version. Empty =
	// gate disarmed (always emit, today's behavior).
	stopLegacyParamsVersion string
	allowedReturnURLs       []string
}

func NewOAuthHandler(
	providers []service.OAuthProvider,
	users *service.UserService,
	devices *service.DeviceService,
	tokens *auth.TokenService,
	cookies *auth.CookieManager,
	trustProxyHeaders, quickLoginRequireSecret bool,
	googleClientID string,
	stopLegacyParamsVersion string,
	allowedReturnURLs []string,
	trustedProxies ...*pkg.TrustedProxies,
) *OAuthHandler {
	h := &OAuthHandler{
		providers:               map[string]service.OAuthProvider{},
		users:                   users,
		devices:                 devices,
		tokens:                  tokens,
		cookies:                 cookies,
		trustProxyHeaders:       trustProxyHeaders,
		quickLoginRequireSecret: quickLoginRequireSecret,
		clientID:                googleClientID,
		stopLegacyParamsVersion: stopLegacyParamsVersion,
		allowedReturnURLs:       append([]string(nil), allowedReturnURLs...),
	}
	if len(trustedProxies) == 1 {
		h.trustedProxies = trustedProxies[0]
	}
	for _, p := range providers {
		h.providers[p.Name()] = p
		h.order = append(h.order, p.Name())
	}
	return h
}

// ProviderNames lists the configured providers (registration order).
func (h *OAuthHandler) ProviderNames() []string { return h.order }

// Providers (GET /oidc/providers) lets the login page render only the
// providers this deployment actually serves. Additive public endpoint.
func (h *OAuthHandler) Providers(c *gin.Context) {
	OK(c, gin.H{"providers": h.order})
}

// stateCookieName is the per-provider signed cookie carrying the CSRF state.
func stateCookieName(provider string) string { return "oauth_state_" + provider }

// Authorize (POST /oidc/{provider}) stashes returnTo/deviceId in signed
// cookies and redirects to the provider consent page. The frontend sends
// parameters as a form body (x-www-form-urlencoded); Spring's @RequestParam
// read query + body, so FormValue keeps that parity (google behavior).
func (h *OAuthHandler) Authorize(c *gin.Context, name string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	provider, ok := h.providers[name]
	if !ok {
		c.String(http.StatusNotFound, "Unknown provider")
		return
	}
	returnTo := c.Request.FormValue("returnTo")
	if returnTo == "" {
		c.String(http.StatusBadRequest, "missing returnTo")
		return
	}
	client := c.Request.FormValue("client")
	if !h.allowedReturnTo(returnTo, client) {
		c.String(http.StatusBadRequest, "invalid returnTo")
		return
	}
	h.cookies.Set(c, "returnTo", returnTo)
	if deviceID := c.Request.FormValue("deviceId"); deviceID != "" {
		h.cookies.Set(c, "deviceId", deviceID)
	}
	// MCP grant flow (doc 16 §3.3): the host tool marks its login with
	// client=mcp and carries a random req binding that must round-trip the
	// redirect. Only the whitelisted value is stashed — anything else is
	// ignored, so unknown params can never smuggle in a different flow. A
	// non-MCP authorize also clears leftover markers, so an aborted MCP
	// login can never poison a later browser login on the same browser.
	if client := c.Request.FormValue("client"); client == "mcp" {
		req := c.Request.FormValue("req")
		if req == "" || len(req) > 128 || !auth.ValidMcpChallenge(c.Request.FormValue("code_challenge")) || c.Request.FormValue("code_challenge_method") != "S256" {
			c.String(http.StatusBadRequest, "MCP requires req and S256 code_challenge")
			return
		}
		h.cookies.SetWithMaxAge(c, "mcpClient", client, 600)
		h.cookies.SetWithMaxAge(c, "mcpReq", req, 600)
		h.cookies.SetWithMaxAge(c, "mcpChallenge", c.Request.FormValue("code_challenge"), 600)
	} else {
		h.cookies.Clear(c, "mcpClient")
		h.cookies.Clear(c, "mcpReq")
		h.cookies.Clear(c, "mcpChallenge")
	}
	state := ""
	if provider.RequiresState() {
		state = randomState()
		h.cookies.SetWithMaxAge(c, stateCookieName(name), state, 600)
	}
	c.Redirect(http.StatusFound, provider.AuthURL(h.baseURL(c), state))
}

// Callback (GET /oauth2/code/{provider}, POST for form_post providers)
// validates state, exchanges the code and upserts the user. Binding still
// requires the separate authenticated confirmation and device exchange.
// Error paths return plain-text bodies (browser-facing), matching legacy.
func (h *OAuthHandler) Callback(c *gin.Context, name string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	provider, ok := h.providers[name]
	if !ok {
		c.String(http.StatusNotFound, "Unknown provider")
		return
	}
	returnTo := h.cookies.Get(c, "returnTo")
	if returnTo == "" {
		c.String(http.StatusBadRequest, "No returnTo cookie found")
		return
	}
	h.cookies.Clear(c, "deviceId")
	h.cookies.Clear(c, "returnTo")
	// MCP grant markers are read and cleared up front — a stale mcpClient
	// cookie (user aborted an MCP login mid-flow) must never leak into a
	// later browser login on the same browser.
	mcpClient := h.cookies.Get(c, "mcpClient")
	mcpReq := h.cookies.Get(c, "mcpReq")
	mcpChallenge := h.cookies.Get(c, "mcpChallenge")
	h.cookies.Clear(c, "mcpClient")
	h.cookies.Clear(c, "mcpReq")
	h.cookies.Clear(c, "mcpChallenge")

	// Revalidate even a correctly signed cookie: it may predate a policy
	// change or come from an older server during rolling deployment.
	if !h.allowedReturnTo(returnTo, mcpClient) {
		c.String(http.StatusBadRequest, "invalid returnTo")
		return
	}
	googleState := ""
	if provider.RequiresState() {
		want := h.cookies.Get(c, stateCookieName(name))
		h.cookies.Clear(c, stateCookieName(name))
		got := requestValue(c, "state")
		if name == "google" {
			googleState = want
		}
		if want == "" || got == "" || got != want {
			c.String(http.StatusBadRequest, "state mismatch")
			return
		}
	}

	// Apple's form_post delivers the profile (`user` field) only on the
	// user's first authorization; providers that don't consume it ignore the
	// context value.
	callbackUser := requestValue(c, "user")
	ctx := service.WithCallbackUser(c.Request.Context(), callbackUser)
	if name == "google" {
		ctx = service.WithGoogleState(ctx, googleState)
	}
	ident, err := provider.Exchange(ctx, requestValue(c, "code"), h.baseURL(c))
	if err != nil || ident == nil || ident.ProviderUserID == "" {
		c.String(http.StatusBadGateway, "Token endpoint returned an invalid response")
		return
	}

	userID, err := h.users.UpsertByIdentity(c.Request.Context(), name, ident)
	if err != nil {
		slog.Error("oauth operation failed", "operation", "user_upsert", "error_type", fmt.Sprintf("%T", err))
		c.String(http.StatusInternalServerError, "Unable to complete login")
		return
	}

	// MCP grant flow (doc 16 §1): mint a one-time grant code instead of a
	// session — a Login here would revoke the user's browser session
	// (single-session model) and ride full account power through the 302.
	// The code is bound to the MCP-generated req; POST /mcp/token burns it
	// in exchange for the dedicated long-lived MCP token.
	if mcpClient == "mcp" {
		if mcpReq == "" || !auth.ValidMcpChallenge(mcpChallenge) {
			c.String(http.StatusBadRequest, "mcp grant binding lost")
			return
		}
		code, err := h.tokens.IssueMcpGrantCode(c.Request.Context(), userID, mcpReq, mcpChallenge)
		if err != nil {
			c.String(http.StatusInternalServerError, "grant code mint failed")
			return
		}
		q := url.Values{}
		q.Set("code", code)
		q.Set("req", mcpReq)
		sep := "?"
		if strings.Contains(returnTo, "?") {
			sep = "&"
		}
		c.Redirect(http.StatusFound, returnTo+sep+q.Encode())
		return
	}

	// Browser callbacks never carry authentication credentials in a URL.
	tokenValue, err := h.tokens.Login(c.Request.Context(), userID, "")
	if err != nil {
		c.String(http.StatusInternalServerError, "Unable to complete login")
		return
	}
	auth.SetBrowserSessionCookie(c.Writer, tokenValue)
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(http.StatusFound, returnTo)
}

// QuickLogin is retired: possession of a device credential must not grant
// an owner account session. Keep a tombstone for legacy clients; callers must
// use the normal user OAuth flow instead. Never look up the device or mint a token.
func (h *OAuthHandler) QuickLogin(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	c.String(http.StatusGone, "Quick login is no longer supported; sign in with your account")
}

// stopLegacyPairingParams reports whether the google pairing redirect should
// omit clientId/oidcGoogle for this device: only when the phase-C gate is
// armed (threshold configured) AND the device's cloud_version is at or above
// the threshold. Everything uncertain — empty threshold, web login, lookup
// error, unknown/unparseable version, malformed threshold — keeps the legacy
// params: omitting them is the one breaking direction of the migration, so
// the gate fails safe (doc 05 §3.1).
func (h *OAuthHandler) stopLegacyPairingParams(c *gin.Context, deviceID string) bool {
	if h.stopLegacyParamsVersion == "" || deviceID == "" {
		return false
	}
	threshold, err := pkg.ParseVersion(h.stopLegacyParamsVersion)
	if err != nil {
		return false
	}
	dev, err := h.devices.GetByID(c.Request.Context(), deviceID)
	if err != nil {
		return false
	}
	reported := service.WebVersionFromCloudVersion(dev.CloudVersion)
	if reported == "" {
		return false // first pairing / never reported: conservative default
	}
	v, err := pkg.ParseVersion(reported)
	if err != nil {
		return false
	}
	return pkg.Compare(v, threshold) >= 0
}

func randomState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand never fails since Go 1.24
	return hex.EncodeToString(b)
}

// requestValue reads a callback parameter from the query string, falling
// back to the POST form body. Google/GitHub/Microsoft redirect with query
// parameters (unchanged, query wins); Apple's response_mode=form_post
// delivers code/state/user as x-www-form-urlencoded POST fields.
func requestValue(c *gin.Context, name string) string {
	if v := c.Query(name); v != "" {
		return v
	}
	return c.PostForm(name)
}

// baseURL derives scheme://host[:port] for the OAuth redirect_uri template.
// Forwarded scheme/host are accepted only from a configured immediate proxy.
func (h *OAuthHandler) baseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.Request.Host
	if h.trustProxyHeaders && h.trustedProxies.TrustsRequest(c.Request) {
		if p := c.GetHeader("X-Forwarded-Proto"); len(c.Request.Header.Values("X-Forwarded-Proto")) == 1 && (p == "https" || p == "http") {
			scheme = p
		}
		if fh := c.GetHeader("X-Forwarded-Host"); len(c.Request.Header.Values("X-Forwarded-Host")) == 1 && validForwardedHost(fh) {
			host = fh
		} else if c.Request.Host != "" {
			host = c.Request.Host
		}
	}
	// Strip a default port suffix, mirroring the legacy getBaseUrl.
	if strings.HasSuffix(host, ":80") && scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	if strings.HasSuffix(host, ":443") && scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	}
	return scheme + "://" + host
}

func (h *OAuthHandler) allowedReturnTo(raw, client string) bool {
	if client == "mcp" && pkg.AllowedMCPLoopbackReturnURL(raw) {
		return true
	}
	return pkg.AllowedOAuthReturnURL(raw, h.allowedReturnURLs)
}

func validForwardedHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "/\\?#@, \t\r\n") {
		return false
	}
	u, err := url.Parse("https://" + host)
	return err == nil && u.Host == host && u.Hostname() != "" && u.User == nil
}

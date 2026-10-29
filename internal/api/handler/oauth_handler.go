package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
	"github.com/arkkvm/arkkvm-cloud-go/internal/pkg"
	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
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

// OAuthHandler serves the provider OAuth2 flows: one shared
// authorize/callback pair per configured provider plus the device-local
// quick login. The Google branch preserves the legacy wire behavior
// byte-for-byte (golden-locked): no state, callback query carries
// token/clientId/oidcGoogle/deviceId. New providers require state and never
// emit the Google-only parameters.
type OAuthHandler struct {
	providers map[string]service.OAuthProvider
	order     []string // registration order, stable for the providers endpoint

	users   oauthUsers
	devices oauthDevices
	tokens  *auth.TokenService
	cookies *auth.CookieManager

	trustProxyHeaders       bool
	quickLoginRequireSecret bool
	clientID                string // legacy callback parameter (google only)
	// Phase-C gate: stop clientId/oidcGoogle on google pairing
	// redirects when the device's cloud_version >= this version. Empty =
	// gate disarmed (always emit, today's behavior).
	stopLegacyParamsVersion string
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
	h.cookies.Set(c, "returnTo", returnTo)
	if deviceID := c.Request.FormValue("deviceId"); deviceID != "" {
		h.cookies.Set(c, "deviceId", deviceID)
	}
	// MCP grant flow: the host tool marks its login with
	// client=mcp and carries a random req binding that must round-trip the
	// redirect. Only the whitelisted value is stashed — anything else is
	// ignored, so unknown params can never smuggle in a different flow. A
	// non-MCP authorize also clears leftover markers, so an aborted MCP
	// login can never poison a later browser login on the same browser.
	if client := c.Request.FormValue("client"); client == "mcp" {
		req := c.Request.FormValue("req")
		if req == "" {
			c.String(http.StatusBadRequest, "missing req for mcp client")
			return
		}
		h.cookies.SetWithMaxAge(c, "mcpClient", client, 600)
		h.cookies.SetWithMaxAge(c, "mcpReq", req, 600)
	} else {
		h.cookies.Clear(c, "mcpClient")
		h.cookies.Clear(c, "mcpReq")
	}
	state := ""
	if provider.RequiresState() {
		state = randomState()
		h.cookies.SetWithMaxAge(c, stateCookieName(name), state, 600)
	}
	c.Redirect(http.StatusFound, provider.AuthURL(h.baseURL(c), state))
}

// Callback (GET /oauth2/code/{provider}, POST for form_post providers)
// exchanges the code, validates the state (new providers), upserts the user,
// optionally binds the device, then redirects back with the session token.
// Error paths return plain-text bodies (browser-facing), matching legacy.
func (h *OAuthHandler) Callback(c *gin.Context, name string) {
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
	deviceID := h.cookies.Get(c, "deviceId")
	h.cookies.Clear(c, "deviceId")
	h.cookies.Clear(c, "returnTo")
	// MCP grant markers are read and cleared up front — a stale mcpClient
	// cookie (user aborted an MCP login mid-flow) must never leak into a
	// later browser login on the same browser.
	mcpClient := h.cookies.Get(c, "mcpClient")
	mcpReq := h.cookies.Get(c, "mcpReq")
	h.cookies.Clear(c, "mcpClient")
	h.cookies.Clear(c, "mcpReq")

	if provider.RequiresState() {
		want := h.cookies.Get(c, stateCookieName(name))
		h.cookies.Clear(c, stateCookieName(name))
		got := requestValue(c, "state")
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
	ident, err := provider.Exchange(ctx, requestValue(c, "code"), h.baseURL(c))
	if err != nil || ident == nil || ident.ProviderUserID == "" {
		c.String(http.StatusBadGateway, "Token endpoint returned an invalid response")
		return
	}
	// Log presence only: never log profile values, callback payloads or tokens.
	slog.Info("oauth profile received", "provider", name,
		"callback_user_present", strings.TrimSpace(callbackUser) != "",
		"name_present", strings.TrimSpace(ident.DisplayName) != "",
		"email_present", strings.TrimSpace(ident.Email) != "",
		"avatar_present", strings.TrimSpace(ident.AvatarURL) != "")

	userID, err := h.users.UpsertByIdentity(c.Request.Context(), name, ident)
	if err != nil {
		c.String(http.StatusInternalServerError, "user upsert failed: "+err.Error())
		return
	}
	slog.Info("oauth profile saved", "provider", name, "user_id", userID)

	// MCP grant flow: mint a one-time grant code instead of a
	// session — a Login here would revoke the user's browser session
	// (single-session model) and ride full account power through the 302.
	// The code is bound to the MCP-generated req; POST /mcp/token burns it
	// in exchange for the dedicated long-lived MCP token.
	if mcpClient == "mcp" {
		if mcpReq == "" {
			c.String(http.StatusBadRequest, "mcp grant binding lost")
			return
		}
		code, err := h.tokens.IssueMcpGrantCode(c.Request.Context(), userID, mcpReq)
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

	var tokenValue string
	if deviceID == "" {
		tokenValue, err = h.tokens.Login(c.Request.Context(), userID, "")
	} else {
		// OAuth does not bind a device or authorize credential exchange. Keep
		// the callback token for redirect compatibility; only the token from
		// explicit POST /devices/:id/bind confirmation can be exchanged.
		tokenValue, err = h.tokens.IssuePairingToken(c.Request.Context(), userID, deviceID)
	}
	if err != nil {
		c.String(http.StatusInternalServerError, "login failed: "+err.Error())
		return
	}

	// Legacy google callback parameters: clientId (firmware pairing aud) and
	// oidcGoogle (firmware register payload) ride along until the phase-C
	// gate stops them; new providers never emit them. Web logins (no
	// deviceId) are never gated — there is no device version to consult and
	// the params are harmless there.
	q := url.Values{}
	q.Set("token", tokenValue)
	if name == "google" && !h.stopLegacyPairingParams(c, deviceID) {
		q.Set("clientId", h.clientID)
		q.Set("oidcGoogle", ident.RawIDToken)
	}
	if deviceID != "" {
		q.Set("deviceId", deviceID)
		// The OAuth-only pairing token above is not a web session. The cloud
		// webapp still needs a live session, so mint a plain login token the
		// device webapp forwards through app /ad-login?sn=1.
		// On failure omit the param — the handoff degrades to today's
		// second-login behavior instead of breaking pairing.
		if loginToken, lerr := h.tokens.Login(c.Request.Context(), userID, ""); lerr == nil {
			q.Set("loginToken", loginToken)
		} else {
			slog.Warn("oauth callback: loginToken mint failed; cloud webapp handoff falls back to a second login", "provider", name, "error", lerr)
		}
	}
	sep := "?"
	if strings.Contains(returnTo, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, returnTo+sep+q.Encode())
}

// QuickLogin (GET /oidc/quick): returns a bare session token for the device
// owner. Hardened: the device secretToken must accompany the
// deviceId; without it the endpoint answers 404 and leaks nothing.
func (h *OAuthHandler) QuickLogin(c *gin.Context) {
	deviceID := c.Query("deviceId")
	if deviceID == "" {
		c.String(http.StatusNotFound, "Device not found")
		return
	}
	if h.quickLoginRequireSecret {
		secret := c.Query("secretToken")
		if secret == "" {
			c.String(http.StatusNotFound, "Device not found")
			return
		}
		resolvedID, _, err := h.devices.FindBySecretToken(c.Request.Context(), secret)
		if err != nil || resolvedID != deviceID {
			c.String(http.StatusNotFound, "Device not found")
			return
		}
	}
	dev, err := h.devices.GetByID(c.Request.Context(), deviceID)
	if err != nil {
		c.String(http.StatusNotFound, "Device not found")
		return
	}
	token, err := h.tokens.Login(c.Request.Context(), dev.UserID, "")
	if err != nil {
		c.String(http.StatusInternalServerError, "login failed: "+err.Error())
		return
	}
	c.String(http.StatusOK, token)
}

// stopLegacyPairingParams reports whether the google pairing redirect should
// omit clientId/oidcGoogle for this device: only when the phase-C gate is
// armed (threshold configured) AND the device's cloud_version is at or above
// the threshold. Everything uncertain — empty threshold, web login, lookup
// error, unknown/unparseable version, malformed threshold — keeps the legacy
// params: omitting them is the one breaking direction of the migration, so
// the gate fails safe.
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
// With trustProxyHeaders the X-Forwarded-Proto/Host/Port headers win (the
// deployed branch enabled the equivalent forward-headers-strategy=native).
func (h *OAuthHandler) baseURL(c *gin.Context) string {
	scheme := "http"
	host := c.Request.Host
	if h.trustProxyHeaders {
		if p := c.GetHeader("X-Forwarded-Proto"); p != "" {
			scheme = p
		}
		if fh := c.GetHeader("X-Forwarded-Host"); fh != "" {
			host = fh
		} else if c.Request.Host != "" {
			host = c.Request.Host
		}
	} else if c.Request.TLS != nil {
		scheme = "https"
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

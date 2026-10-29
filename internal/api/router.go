package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/arkkvm/arkkvm-cloud-go/internal/api/handler"
	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
)

// Deps bundles everything the router needs (wired in cmd/server/main.go).
type Deps struct {
	Tokens  *auth.TokenService
	Mcp     *handler.McpHandler
	Users   *handler.UserHandler
	Devices *handler.DeviceHandler
	OAuth   *handler.OAuthHandler
	Release *handler.ReleaseHandler
	Webrtc  *handler.WebrtcHandler
	IP      *handler.IPHandler

	// McpTokens authenticates the dedicated arkkvm_mcp credential.
	McpTokens *auth.McpTokenService

	// ReadyCheck backs /readyz (MySQL + Redis connectivity).
	ReadyCheck func() error
	// DeviceWS and ClientWS are the raw WebSocket handlers (http.Handler).
	DeviceWS http.Handler
	ClientWS http.Handler
}

// NewRouter assembles the route table with the legacy-accurate
// public/protected split: everything except /oidc/**,
// /oauth2/**, /releases/**, /ip, /favicon.ico, the two device-self endpoints and
// the WebSocket channels requires a bearer token.
func NewRouter(d Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), auth.CORS([]string{"*"}))

	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/readyz", func(c *gin.Context) {
		if d.ReadyCheck != nil {
			if err := d.ReadyCheck(); err != nil {
				c.String(http.StatusServiceUnavailable, "not ready: %v", err)
				return
			}
		}
		c.Status(http.StatusOK)
	})

	// WebSocket channels (handshake auth lives inside the endpoints).
	r.GET("/", func(c *gin.Context) { d.DeviceWS.ServeHTTP(c.Writer, c.Request) })
	r.GET("/webrtc/signaling/client", func(c *gin.Context) { d.ClientWS.ServeHTTP(c.Writer, c.Request) })

	// Public REST.
	public := r.Group("/")
	{
		if d.IP != nil {
			public.GET("/ip", d.IP.Get)
		}
		// One authorize/callback pair per configured provider; static routes
		// (not :provider) so /oidc/providers coexists without a gin conflict.
		// Google rides the same pair with legacy wire behavior (no state,
		// google-only callback params) — the handler branches by provider.
		//
		// GET is served alongside the legacy POST: Chromium refuses a
		// cross-subdomain form POST under a form-action CSP even when the
		// target host is allow-listed, so the login page navigates instead.
		// Authorize reads query and form alike, so both verbs behave the same.
		// The callback mirrors both verbs for the reverse reason: Apple's
		// response_mode=form_post delivers code/state as a POST body.
		for _, name := range d.OAuth.ProviderNames() {
			name := name
			authorize := func(c *gin.Context) { d.OAuth.Authorize(c, name) }
			public.POST("/oidc/"+name, authorize)
			public.GET("/oidc/"+name, authorize)
			public.GET("/oauth2/code/"+name, func(c *gin.Context) { d.OAuth.Callback(c, name) })
			public.POST("/oauth2/code/"+name, func(c *gin.Context) { d.OAuth.Callback(c, name) })
		}
		public.GET("/oidc/providers", d.OAuth.Providers)
		public.GET("/oidc/quick", d.OAuth.QuickLogin)
		public.GET("/releases", d.Release.Retrieve)
		public.POST("/devices/token", d.Devices.ExchangeToken)
		public.DELETE("/devices/:id", d.Devices.Unbind) // device self-auth via secretToken
		// MCP credential endpoints: the grant-code exchange is
		// public (the code itself is the secret); self-revoke requires the
		// MCP credential and must reject sessions.
		public.POST("/mcp/token", d.Mcp.ExchangeToken)
	}

	// MCP-authenticated REST: self-revoke only.
	mcpAuthed := r.Group("/", auth.RequireMcp(d.McpTokens))
	{
		mcpAuthed.POST("/mcp/revoke", d.Mcp.Revoke)
	}

	// Protected REST.
	authed := r.Group("/", auth.RequireAuth(d.Tokens))
	{
		authed.GET("/me", d.Users.Me)
		authed.GET("/logout", d.Users.Logout)
		// The three routes the MCP credential may use: session
		// resolution first (unchanged for browsers), MCP token as fallback.
		// Everything below stays session-only, keeping the MCP power surface
		// a fixed allowlist.
		mcpReads := r.Group("/", auth.RequireAuthOrMcp(d.Tokens, d.McpTokens))
		{
			mcpReads.GET("/devices", d.Devices.List)
			mcpReads.GET("/devices/:id", d.Devices.Get)
			mcpReads.POST("/webrtc/ice_config", d.Webrtc.IceConfig)
		}
		authed.POST("/devices/:id/bind", d.Devices.Bind)
		authed.PUT("/devices/:id", d.Devices.Update)
		authed.DELETE("/cloud/devices/:id", d.Devices.CloudUnbind)
		authed.POST("/webrtc/session", d.Webrtc.CreateSession)
		authed.POST("/webrtc/turn_activity", d.Webrtc.TurnActivity)
	}

	// Legacy also excluded favicon.ico from auth; answer with an empty 204.
	r.GET("/favicon.ico", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	return r
}

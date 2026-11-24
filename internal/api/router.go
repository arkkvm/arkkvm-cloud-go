package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"arkkvm.com/arkkvm-cloud/internal/api/handler"
	"arkkvm.com/arkkvm-cloud/internal/auth"
)

// Deps bundles everything the router needs (wired in cmd/server/main.go).
type Deps struct {
	BrowserOrigins []string
	Tokens         *auth.TokenService
	Mcp            *handler.McpHandler
	Users          *handler.UserHandler
	Devices        *handler.DeviceHandler
	OAuth          *handler.OAuthHandler
	Release        *handler.ReleaseHandler
	Webrtc         *handler.WebrtcHandler
	IP             *handler.IPHandler

	// McpTokens authenticates the dedicated arkkvm_mcp credential (doc 16).
	McpTokens *auth.McpTokenService

	// ReadyCheck backs /readyz (MySQL + Redis connectivity).
	ReadyCheck func() error
	// DeviceWS and ClientWS are the raw WebSocket handlers (http.Handler).
	DeviceWS http.Handler
	ClientWS http.Handler
}

// NewRouter assembles the route table with the legacy-accurate
// public/protected split (doc 02 §0.2): everything except /oidc/**,
// /oauth2/**, /releases/**, /ip, /favicon.ico, the two device-self endpoints and
// the WebSocket channels requires a bearer token.
func NewRouter(d Deps) *gin.Engine {
	r := gin.New()
	legacyCORS := auth.CORS([]string{"*"})
	r.Use(requestRecovery(slog.Default()), func(c *gin.Context) {
		c.Writer.Header().Add("Vary", "Origin")
		if auth.IsAllowedBrowserOrigin(c.GetHeader("Origin"), d.BrowserOrigins) {
			c.Header("Access-Control-Allow-Origin", c.GetHeader("Origin"))
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
			c.Header("Access-Control-Expose-Headers", auth.CSRFHeader)
			if c.Request.Method == http.MethodGet && c.Request.URL.Path == "/me" {
				c.Header("Access-Control-Expose-Headers", auth.CSRFHeader+", "+auth.SessionReferenceHeader)
			}
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
			return
		}
		legacyCORS(c)
	})

	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/readyz", func(c *gin.Context) {
		if d.ReadyCheck != nil {
			if err := d.ReadyCheck(); err != nil {
				c.String(http.StatusServiceUnavailable, "not ready")
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
		// Google retains legacy pairing fields while enforcing state/nonce.
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
		public.POST("/device-bindings", d.Devices.CreateBindingRequest)
		public.GET("/device-bindings/:requestId/status", d.Devices.BindingRequestStatus)
		public.POST("/devices/token", d.Devices.ExchangeToken)
		public.DELETE("/devices/:id", d.Devices.Unbind) // device self-auth via secretToken
		// MCP credential endpoints (doc 16 §3.4): the grant-code exchange is
		// public (the code itself is the secret); self-revoke requires the
		// MCP credential and must reject sessions.
		public.POST("/mcp/token", d.Mcp.ExchangeToken)
	}

	// MCP-authenticated REST (doc 16): self-revoke only.
	mcpAuthed := r.Group("/", auth.RequireMcp(d.McpTokens))
	{
		mcpAuthed.POST("/mcp/revoke", d.Mcp.Revoke)
	}

	// Protected REST.
	authed := r.Group("/", auth.RequireAuth(d.Tokens, d.BrowserOrigins))
	{
		authed.GET("/me", d.Users.Me)
		authed.GET("/logout", d.Users.Logout)
		authed.POST("/logout", d.Users.Logout)
		// The three routes the MCP credential may use (doc 16 §2):
		// Cookie authentication for browsers, dedicated Bearer only for MCP.
		// Everything below stays session-only, keeping the MCP power surface
		// a fixed allowlist.
		mcpReads := r.Group("/", auth.RequireAuthOrMcp(d.Tokens, d.McpTokens, d.BrowserOrigins))
		{
			mcpReads.GET("/devices", d.Devices.List)
			mcpReads.GET("/devices/:id", d.Devices.Get)
			mcpReads.POST("/webrtc/ice_config", d.Webrtc.IceConfig)
		}
		authed.GET("/device-bindings/:requestId", d.Devices.BindingRequest)
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

// Gin's default panic diagnostics can dump Cookie or legacy query credentials.
// Recover inside this route so the outer recovery cannot emit them.
func requestRecovery(logger *slog.Logger) gin.HandlerFunc {
	return gin.RecoveryWithWriter(nil, func(c *gin.Context, value any) {
		logger.Error("request panic", "method", c.Request.Method,
			"route", c.FullPath(), "panic_type", fmt.Sprintf("%T", value))
		if !c.Writer.Written() {
			c.AbortWithStatus(http.StatusInternalServerError)
		} else {
			c.Abort()
		}
	})
}

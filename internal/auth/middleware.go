package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// userIDKey is the gin context key holding the authenticated user id.
const userIDKey = "auth.userID"

// BearerToken extracts the token from an "Authorization: Bearer <token>"
// header. Missing prefix or empty token yields "".
func BearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// abort401 emits the legacy NotLoginException-shaped 401 (shared by every
// auth middleware so the wire body never drifts).
func abort401(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"message": "token invalid or expired",
		"code":    0,
		"data":    nil,
	})
}

// RequireAuth validates the bearer token and stores the user id in the
// context. Unauthenticated requests abort with 401 in the BaseResult shape
// (mirroring the legacy NotLoginException handler).
func RequireAuth(tokens *TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := BearerToken(c.GetHeader("Authorization"))
		userID, _, err := tokens.Resolve(c.Request.Context(), token)
		if err != nil {
			abort401(c)
			return
		}
		c.Set(userIDKey, userID)
		c.Next()
	}
}

// RequireAuthOrMcp guards the routes the MCP credential may use: session resolution runs first with unchanged semantics for browser
// clients; only its failure falls back to the dedicated MCP token. Any other
// route keeps plain RequireAuth, so the MCP power surface stays a fixed
// allowlist.
func RequireAuthOrMcp(tokens *TokenService, mcp *McpTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := BearerToken(c.GetHeader("Authorization"))
		userID, _, err := tokens.Resolve(c.Request.Context(), token)
		if err == nil {
			c.Set(userIDKey, userID)
			c.Next()
			return
		}
		if mcp != nil {
			if mcpID, merr := mcp.Resolve(c.Request.Context(), token); merr == nil {
				c.Set(userIDKey, mcpID)
				c.Next()
				return
			}
		}
		abort401(c)
	}
}

// RequireMcp authenticates the dedicated MCP credential ONLY:
// used by POST /mcp/revoke. Sessions are deliberately rejected — a web
// session must never implicitly revoke MCP credentials.
func RequireMcp(mcp *McpTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := BearerToken(c.GetHeader("Authorization"))
		userID, err := mcp.Resolve(c.Request.Context(), token)
		if err != nil {
			abort401(c)
			return
		}
		c.Set(userIDKey, userID)
		c.Next()
	}
}

// UserID reads the authenticated user id (0 when absent).
func UserID(c *gin.Context) int64 {
	if v, ok := c.Get(userIDKey); ok {
		if id, ok := v.(int64); ok {
			return id
		}
	}
	return 0
}

// CORS mirrors the legacy SaServletFilter: permissive CORS headers on every
// response, OPTIONS short-circuits. allowOrigins=["*"] reproduces the current
// behavior; tighten via config when the frontend origins are pinned down.
func CORS(allowOrigins []string) gin.HandlerFunc {
	allow := strings.Join(allowOrigins, ",")
	if allow == "" {
		allow = "*"
	}
	return func(c *gin.Context) {
		h := c.Writer.Header()
		if len(allowOrigins) == 1 && allowOrigins[0] == "*" {
			h.Set("Access-Control-Allow-Origin", "*")
		} else if len(allowOrigins) > 0 {
			origin := c.GetHeader("Origin")
			for _, o := range allowOrigins {
				if o == origin {
					h.Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		}
		h.Set("Access-Control-Allow-Methods", "*")
		h.Set("Access-Control-Allow-Headers", "*")
		h.Set("Access-Control-Max-Age", "3600")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

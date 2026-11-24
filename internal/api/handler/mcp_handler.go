package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"arkkvm.com/arkkvm-cloud/internal/auth"
)

// McpHandler serves the arkkvm_mcp credential endpoints (doc 16 §3.4):
// POST /mcp/token exchanges a one-time grant code for the long-lived MCP
// token; POST /mcp/revoke self-revokes the presented token.
type McpHandler struct {
	codes  *auth.TokenService
	tokens *auth.McpTokenService
}

func NewMcpHandler(codes *auth.TokenService, tokens *auth.McpTokenService) *McpHandler {
	return &McpHandler{codes: codes, tokens: tokens}
}

type mcpTokenRequest struct {
	Code         string `json:"code"`
	Req          string `json:"req"`
	CodeVerifier string `json:"codeVerifier"`
}

// ExchangeToken (POST /mcp/token) burns the grant code, verifies the req
// binding and mints the MCP token. Every failure answers 401 in BaseResult
// shape: the code is single-use and burned on each attempt, so a req guess
// gets exactly one shot per code.
func (h *McpHandler) ExchangeToken(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	var body mcpTokenRequest
	if err := c.ShouldBindJSON(&body); err != nil || body.Code == "" || body.Req == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "invalid grant code",
			"code":    0,
			"data":    nil,
		})
		return
	}
	userID, err := h.codes.ExchangeMcpGrant(c.Request.Context(), body.Code, body.Req, body.CodeVerifier)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "invalid grant code",
			"code":    0,
			"data":    nil,
		})
		return
	}

	token, err := h.tokens.Issue(c.Request.Context(), userID)
	if err != nil {
		FailCode(c, 500, "token mint failed")
		return
	}
	OK(c, gin.H{"token": token, "tokenType": "mcp"})
}

// Revoke (POST /mcp/revoke) self-revokes the presented MCP token,
// idempotently (unknown or already-revoked tokens still answer success).
func (h *McpHandler) Revoke(c *gin.Context) {
	if err := h.tokens.Revoke(c.Request.Context(), auth.BearerToken(c.GetHeader("Authorization"))); err != nil {
		FailCode(c, 500, "revoke failed")
		return
	}
	OK(c, gin.H{"revoked": true})
}

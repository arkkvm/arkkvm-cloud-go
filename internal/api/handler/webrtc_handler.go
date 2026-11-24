// Package handler — webrtc endpoints.
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"arkkvm.com/arkkvm-cloud/internal/auth"
	"arkkvm.com/arkkvm-cloud/internal/model"
	"arkkvm.com/arkkvm-cloud/internal/repository"
	"arkkvm.com/arkkvm-cloud/internal/service"
)

// WebrtcHandler serves the WebRTC helper endpoints (doc 02 §1.6).
type WebrtcHandler struct {
	turn    *service.TurnService
	turnLog *repository.TurnActivityRepo
}

func NewWebrtcHandler(turn *service.TurnService, turnLog *repository.TurnActivityRepo) *WebrtcHandler {
	return &WebrtcHandler{turn: turn, turnLog: turnLog}
}

// The retired one-shot HTTP offer cannot enforce a credential-bound lease.
// All new sessions must use the authenticated, continuously checked socket.
func (h *WebrtcHandler) CreateSession(c *gin.Context) {
	c.JSON(http.StatusGone, BaseResult[any]{Success: false, Code: http.StatusGone, Message: "use authenticated WebSocket signaling"})
}

// IceConfig (POST /webrtc/ice_config) proxies the Cloudflare TURN credential
// endpoint and strips turns: URLs.
func (h *WebrtcHandler) IceConfig(c *gin.Context) {
	ice, err := h.turn.GenerateCredentials(c.Request.Context())
	if err != nil || ice == nil {
		Fail(c, "failed to obtain ICE configuration")
		return
	}
	OK(c, gin.H{"iceServers": ice})
}

type turnActivityRequest struct {
	BytesReceived int64 `json:"bytesReceived"`
	BytesSent     int64 `json:"bytesSent"`
}

// TurnActivity (POST /webrtc/turn_activity) records per-session TURN traffic.
func (h *WebrtcHandler) TurnActivity(c *gin.Context) {
	var req turnActivityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		FailCode(c, http.StatusInternalServerError, "invalid payload")
		return
	}
	if err := h.turnLog.Create(&model.TurnActivity{
		UserID:        auth.UserID(c),
		BytesSent:     req.BytesSent,
		BytesReceived: req.BytesReceived,
	}); err != nil {
		FailCode(c, http.StatusInternalServerError, "failed to record turn activity")
		return
	}
	OKEmpty(c)
}

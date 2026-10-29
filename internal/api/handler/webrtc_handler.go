// Package handler — webrtc endpoints.
package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
	"github.com/arkkvm/arkkvm-cloud-go/internal/repository"
	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
	"github.com/arkkvm/arkkvm-cloud-go/internal/ws"
)

// webrtcHub is the signaling-state surface CreateSession needs; *ws.Hub
// implements it. Narrowed so the ownership check (F1) is unit-testable.
type webrtcHub interface {
	IsOnline(deviceID string) bool
	AcquirePending(deviceID string) (*ws.PendingWaiter, bool)
	SendToDevice(deviceID string, payload []byte) bool
}

// deviceOwnership checks device ownership (*service.DeviceService implements
// it). POST /webrtc/session must verify the caller owns the target device:
// the device-side offer validation is dead code (F2), so this check is the
// only authorization gate on the session path (F1).
type deviceOwnership interface {
	BelongsToUser(ctx context.Context, deviceID string, userID int64) (bool, error)
}

// WebrtcHandler serves the WebRTC helper endpoints.
type WebrtcHandler struct {
	hub     webrtcHub
	owner   deviceOwnership
	turn    *service.TurnService
	turnLog *repository.TurnActivityRepo

	// waitTimeout bounds the offer/answer round trip (15s in production,
	// injectable in tests).
	waitTimeout time.Duration
}

func NewWebrtcHandler(hub *ws.Hub, owner deviceOwnership, turn *service.TurnService, turnLog *repository.TurnActivityRepo) *WebrtcHandler {
	return &WebrtcHandler{hub: hub, owner: owner, turn: turn, turnLog: turnLog, waitTimeout: 15 * time.Second}
}

type createSessionRequest struct {
	ID string `json:"id" binding:"required"`
	SD string `json:"sd" binding:"required"`
}

// CreateSession (POST /webrtc/session) implements the completed semantics of
// the half-finished legacy endpoint:
// forward the SDP to the device and wait up to 15s for its frame.
func (h *WebrtcHandler) CreateSession(c *gin.Context) {
	var req createSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		FailCode(c, http.StatusInternalServerError, "id and sd are required")
		return
	}
	if !h.hub.IsOnline(req.ID) {
		Fail(c, "device not found")
		return
	}
	// F1: without ownership validation any logged-in user could push an offer
	// to any online device (the device-side check never runs, F2). Reuse the
	// "device not found" message to avoid leaking device existence.
	belongs, err := h.owner.BelongsToUser(c.Request.Context(), req.ID, auth.UserID(c))
	if err != nil || !belongs {
		Fail(c, "device not found")
		return
	}

	waiter, ok := h.hub.AcquirePending(req.ID)
	if !ok {
		Fail(c, "device is busy")
		return
	}
	defer waiter.Release()

	frame, err := ws.BuildSessionOffer(req.SD)
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "failed to build offer")
		return
	}
	if !h.hub.SendToDevice(req.ID, frame) {
		Fail(c, "device not found")
		return
	}

	payload, err := waiter.Wait(h.waitTimeout)
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "device response timeout")
		return
	}
	OK(c, string(payload))
}

// IceConfig (POST /webrtc/ice_config) proxies the Cloudflare TURN credential
// endpoint and strips turns: URLs.
func (h *WebrtcHandler) IceConfig(c *gin.Context) {
	ice, err := h.turn.GenerateCredentials(c.Request.Context())
	if err != nil || ice == nil {
		msg := "empty response"
		if err != nil {
			msg = err.Error()
		}
		Fail(c, "failed to obtain ICE configuration: "+msg)
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

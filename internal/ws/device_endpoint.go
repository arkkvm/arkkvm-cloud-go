package ws

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"

	"arkkvm.com/arkkvm-cloud/internal/pkg"
)

// DeviceEndpoint serves the device WebSocket channel mounted at "/".
// Handshake order mirrors the legacy DeviceSocketHandleInterceptor (doc 02 §2.1):
// Bearer secretToken lookup -> X-Device-Id match -> version headers -> real IP
// -> cloud_version sync -> upgrade. Handshake failures answer with a proper
// HTTP status (the legacy Spring 200-empty is not a protocol requirement).
type DeviceEndpoint struct {
	OnConnected    func(deviceID, ip string, lifetime context.Context)
	TrustedProxies *pkg.TrustedProxies
	Hub            *Hub
	RealDevice     DeviceStore
	Options        Options
	Log            *slog.Logger
	Lifetime       context.Context // cancelled on server shutdown

	upgrader websocket.Upgrader
}

// DeviceStore is the device persistence needed at handshake time.
type DeviceStore interface {
	// FindBySecretToken resolves the permanent device token to the device row.
	FindBySecretToken(ctx context.Context, secretToken string) (deviceID string, cloudVersion *string, err error)
	// UpdateCloudVersion persists a changed reported version.
	UpdateCloudVersion(ctx context.Context, deviceID, cloudVersion string) error
}

// Options carries the tuned WebSocket parameters (doc 03 §6).
type Options struct {
	SendBuffer        int
	WriteTimeout      time.Duration
	ReadDeadline      time.Duration
	HeartbeatInterval time.Duration
	MaxMessageSize    int64
}

func (e *DeviceEndpoint) init() {
	e.upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     nativeWebSocketRequest,
	}
}

func (e *DeviceEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// This endpoint is firmware-only: reject browser handshakes before any
	// credential lookup or device-version mutation.
	if !nativeWebSocketRequest(r) {
		http.Error(w, "browser origin not allowed", http.StatusForbidden)
		return
	}
	if e.upgrader.CheckOrigin == nil {
		e.init()
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
		http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	secretToken := authHeader[7:]

	deviceID, cloudVersionDB, err := e.RealDevice.FindBySecretToken(r.Context(), secretToken)
	if err != nil {
		e.Log.Warn("device wshandler: device not found for token", "error", err)
		http.Error(w, "device not found", http.StatusUnauthorized)
		return
	}

	headerID := r.Header.Get("X-Device-Id")
	if headerID == "" || headerID != deviceID {
		e.Log.Warn("device wshandler: device id/token mismatch", "header_id", headerID)
		http.Error(w, "device id mismatch", http.StatusUnauthorized)
		return
	}

	// Version headers: new firmware reports X-Web-Version, old reports
	// X-Cloud-Version; both may be absent (no NPE — fixes legacy defect D10).
	deviceVersion := r.Header.Get("X-App-Version")
	cloudVersion := r.Header.Get("X-Cloud-Version")
	if cloudVersion == "" {
		cloudVersion = r.Header.Get("X-Web-Version")
	}
	ignorePing := r.Header.Get("X-Ignore-Ping") == "true"
	realIP := pkg.RealIP(r, e.TrustedProxies)

	if cloudVersion != "" && (cloudVersionDB == nil || *cloudVersionDB != cloudVersion) {
		if err := e.RealDevice.UpdateCloudVersion(r.Context(), deviceID, cloudVersion); err != nil {
			e.Log.Warn("device wshandler: update cloud_version failed", "device_id", deviceID, "error", err)
		}
	}

	headers := http.Header{}
	headers.Set("X-Cloud-Time-Ms", strconv.FormatInt(time.Now().UnixMilli(), 10))
	conn, err := e.upgrader.Upgrade(w, r, headers)
	if err != nil {
		e.Log.Warn("device wshandler: upgrade failed", "device_id", deviceID, "error", err)
		return
	}

	base := newWSConn(e.Lifetime, conn, e.Options.SendBuffer, e.Options.WriteTimeout)
	base.start() // launch the writer goroutine — without it no frame ever leaves this connection
	device := &DeviceConn{
		wsConn:           base,
		DeviceID:         deviceID,
		DeviceVersion:    deviceVersion,
		SessionAuthLease: r.Header.Get("X-Cloud-Session-Auth") == "lease-v1",
		CloudVersion:     cloudVersion,
		IP:               realIP,
	}
	e.Hub.RegisterDevice(device)
	if e.OnConnected != nil {
		e.OnConnected(deviceID, realIP, device.ctx)
	}
	e.Log.Info("device wshandler: device connected",
		"device_id", deviceID, "version", deviceVersion, "cloud_version", cloudVersion, "ip", realIP)

	if !ignorePing {
		go e.heartbeat(device)
	}

	defer func() {
		e.Hub.UnregisterDevice(device) // also fires the last_seen update
		e.Log.Info("device wshandler: device disconnected", "device_id", deviceID)
	}()

	e.readPump(device)
}

// heartbeat sends the (fixed, valid-JSON) server ping every interval; send
// failure closes the connection.
func (e *DeviceEndpoint) heartbeat(device *DeviceConn) {
	ticker := time.NewTicker(e.Options.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := device.SendTo(heartbeatPing); err != nil {
				e.Log.Debug("device heartbeat: send failed, stopping", "device_id", device.DeviceID, "error", err)
				device.Close()
				return
			}
		case <-device.Done():
			return
		}
	}
}

// readPump is the single reader for the device connection.
// No read deadline: X-Ignore-Ping devices send nothing while idle, and the
// legacy service kept them connected indefinitely (the 180s deadline here
// killed every idle device connection on a 3-minute cadence — devices churned
// in a reconnect loop and console sessions never stabilized). Liveness for
// regular devices comes from the server heartbeat (write failure closes);
// ignore-ping devices rely on TCP itself, same as the Java deployment.
func (e *DeviceEndpoint) readPump(device *DeviceConn) {
	device.ws.SetReadLimit(e.Options.MaxMessageSize)
	for {
		_, payload, err := device.ws.ReadMessage()
		if err != nil {
			e.Log.Debug("device wshandler: read closed", "device_id", device.DeviceID, "error", err)
			device.Close()
			return
		}
		if string(payload) == "ping" {
			_ = device.SendTo(pongFrame)
			continue
		}
		e.Hub.DispatchDeviceMessage(device.DeviceID, payload)
	}
}

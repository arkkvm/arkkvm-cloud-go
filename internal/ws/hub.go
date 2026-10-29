package ws

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// DeviceConn carries the attributes captured at handshake time.
type DeviceConn struct {
	*wsConn
	DeviceID      string
	UserID        int64
	DeviceVersion string
	CloudVersion  string
	IP            string
}

// ClientConn is a browser/MCP signaling connection bound to one device.
type ClientConn struct {
	*wsConn
	DeviceID   string
	UserID     int64
	OIDCToken  string
	ClientID   string // cloud-minted; stable for this WS lifetime
	Role       string // user|agent when multiplex
	Multiplex  bool   // registered in role slot
}

// Hub is the in-process signaling state center (single-instance assumption).
// Client demux lives in clients (*ClientRegistry).
type Hub struct {
	mu       sync.RWMutex
	devices  map[string]*DeviceConn
	clients  *ClientRegistry
	pending  map[string]chan []byte

	log          *slog.Logger
	onDeviceLeft func(deviceID string) // updates device.last_seen
}

func NewHub(log *slog.Logger, onDeviceLeft func(string)) *Hub {
	if log == nil {
		log = slog.Default()
	}
	return &Hub{
		devices:      map[string]*DeviceConn{},
		clients:      newClientRegistry(),
		pending:      map[string]chan []byte{},
		log:          log,
		onDeviceLeft: onDeviceLeft,
	}
}

// IsOnline implements service.DevicePresence.
func (h *Hub) IsOnline(deviceID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.devices[deviceID]
	return ok
}

// CloseDevice kicks a device connection (cloud-side unbind). Implements
// service.DevicePresence. Returns whether a connection existed.
func (h *Hub) CloseDevice(deviceID string) bool {
	h.mu.Lock()
	conn, ok := h.devices[deviceID]
	h.mu.Unlock()
	if ok {
		conn.Close()
	}
	return ok
}

// RegisterDevice kicks any previous connection for the device (reconnect
// takes over, legacy behavior) and stores the new one.
func (h *Hub) RegisterDevice(conn *DeviceConn) {
	h.mu.Lock()
	old, had := h.devices[conn.DeviceID]
	h.devices[conn.DeviceID] = conn
	h.mu.Unlock()
	if had && old != conn {
		h.log.Warn("device wshandler: kicking previous connection", "device_id", conn.DeviceID)
		old.Close() // its own defer unregisters; the self-check prevents deleting the new one
	}
}

// UnregisterDevice removes the device entry only when it still points at the
// given connection (guards the takeover race).
func (h *Hub) UnregisterDevice(conn *DeviceConn) {
	h.mu.Lock()
	if h.devices[conn.DeviceID] == conn {
		delete(h.devices, conn.DeviceID)
	}
	h.mu.Unlock()
	if h.onDeviceLeft != nil {
		h.onDeviceLeft(conn.DeviceID)
	}
}

// AddClient registers the signaling client (legacy + optional multiplex).
// Returns a same-role connection that was replaced (caller should Close it).
func (h *Hub) AddClient(conn *ClientConn) (replaced *ClientConn) {
	return h.clients.Add(conn, conn.Multiplex)
}

// PromoteClientRole places conn into the role multiplex slot after clientType
// is known (e.g. from the first offer).
func (h *Hub) PromoteClientRole(conn *ClientConn, role string) (replaced *ClientConn) {
	return h.clients.PromoteMultiplex(conn, role)
}

// RemoveClient releases the signaling session (self-checked).
func (h *Hub) RemoveClient(conn *ClientConn) {
	h.clients.Remove(conn)
}

// ClientConn returns the legacy (last-writer) client for a device (nil if none).
func (h *Hub) ClientConn(deviceID string) *ClientConn {
	return h.clients.Legacy(deviceID)
}

// SendToDevice delivers a frame to the device connection if online.
func (h *Hub) SendToDevice(deviceID string, payload []byte) bool {
	h.mu.RLock()
	conn := h.devices[deviceID]
	h.mu.RUnlock()
	if conn == nil {
		return false
	}
	return conn.SendTo(payload) == nil
}

// Device returns the live device connection (nil when offline); used by the
// client channel to enrich the offer frame with the device IP and version.
func (h *Hub) Device(deviceID string) *DeviceConn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.devices[deviceID]
}

// DispatchDeviceMessage routes a device frame: whitelist, then client_id demux
// with legacy fallback. Also feeds HTTP
// pending waiters for POST /webrtc/session.
func (h *Hub) DispatchDeviceMessage(deviceID string, payload []byte) {
	waiter := h.pendingWaiter(deviceID)

	msgType := messageType(payload)
	if forwardableDeviceType(msgType) {
		clientID := frameClientID(payload)
		client := h.clients.ResolveDelivery(deviceID, clientID)
		if client != nil {
			_ = client.SendTo(payload)
		} else if clientID != "" {
			h.log.Debug("device wshandler: client_id miss, no legacy client",
				"device_id", deviceID, "client_id", clientID, "msg_type", msgType)
		}
	} else {
		h.log.Debug("device wshandler: dropping non-forwardable frame",
			"device_id", deviceID, "msg_type", msgType)
	}

	if waiter != nil {
		select {
		case waiter <- payload:
		default:
		}
	}
	if !h.clients.HasClient(deviceID) && waiter == nil {
		h.log.Info("device wshandler: message callback not found", "device_id", deviceID)
	}
}

func (h *Hub) pendingWaiter(deviceID string) chan []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pending[deviceID]
}

// PendingWaiter is the handle returned by AcquirePending.
type PendingWaiter struct {
	deviceID string
	ch       chan []byte
	hub      *Hub
}

// AcquirePending attaches a one-shot waiter for device frames (used by
// POST /webrtc/session). Release must always be called.
func (h *Hub) AcquirePending(deviceID string) (*PendingWaiter, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.pending[deviceID]; exists {
		return nil, false
	}
	ch := make(chan []byte, 1)
	h.pending[deviceID] = ch
	return &PendingWaiter{deviceID: deviceID, ch: ch, hub: h}, true
}

// Wait blocks for a device frame or the timeout/device-attach signal.
// A client attaching to the device cancels the HTTP waiter: frames then flow
// to the client path, so waiting any longer would only time out.
func (w *PendingWaiter) Wait(timeout time.Duration) ([]byte, error) {
	hub := w.hub
	deviceID := w.deviceID
	clientAttached := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			if hub.clients.HasClient(deviceID) {
				select {
				case clientAttached <- struct{}{}:
				case <-stop:
				}
				return
			}
			select {
			case <-time.After(50 * time.Millisecond):
			case <-stop:
				return
			}
		}
	}()

	select {
	case payload := <-w.ch:
		return payload, nil
	case <-clientAttached:
		return nil, errors.New("device is serving a client connection")
	case <-time.After(timeout):
		return nil, context.DeadlineExceeded
	}
}

// Release detaches the waiter.
func (w *PendingWaiter) Release() {
	w.hub.mu.Lock()
	if w.hub.pending[w.deviceID] == w.ch {
		delete(w.hub.pending, w.deviceID)
	}
	w.hub.mu.Unlock()
}

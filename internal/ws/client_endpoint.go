package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
)

// ClientDeviceStore is the device-side validation surface.
type ClientDeviceStore interface {
	BelongsToUser(ctx context.Context, deviceID string, userID int64) (bool, error)
}

// ClientUserStore resolves the user's stored Google id_token, which the offer
// frame carries to the device as OidcGoogle.
type ClientUserStore interface {
	OIDCToken(ctx context.Context, userID int64) (string, error)
}

// McpTokenResolver optionally accepts the dedicated arkkvm_mcp credential on
// the same signaling path: sessions resolve first with
// unchanged semantics; only their failure falls back to the MCP token.
// *auth.McpTokenService satisfies this interface.
type McpTokenResolver interface {
	Resolve(ctx context.Context, token string) (int64, error)
}

func (e *ClientEndpoint) init() {
	e.upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
}

// resolveUserID authenticates the handshake token: web session first
// (unchanged semantics), MCP credential as the fallback.
func (e *ClientEndpoint) resolveUserID(ctx context.Context, token string) (int64, error) {
	userID, _, err := e.Tokens.Resolve(ctx, token)
	if err == nil {
		return userID, nil
	}
	if e.McpTokens != nil {
		if mcpID, merr := e.McpTokens.Resolve(ctx, token); merr == nil {
			return mcpID, nil
		}
	}
	return 0, auth.ErrInvalidToken
}

// ClientEndpoint serves the browser signaling channel mounted at
// "/webrtc/signaling/client?id=<deviceId>&token=<webToken>". Handshake order
// mirrors the legacy ClientSocketHandlerInterceptor: device
// online -> session token valid -> device belongs to user -> user exists.
type ClientEndpoint struct {
	Hub        *Hub
	Tokens     *auth.TokenService
	McpTokens  McpTokenResolver // optional: enables the MCP credential
	Devices    ClientDeviceStore
	Users      ClientUserStore
	ICEServers []string
	// ICECredIssuer optionally supplies credential-bearing ICE entries
	// (self-hosted/Cloudflare TURN) stamped into each offer frame's additive
	// iceServersCred field; legacy firmware ignores the field.
	ICECredIssuer func() []ICEServerCred
	Options       Options
	Log           *slog.Logger
	Lifetime      context.Context

	upgrader websocket.Upgrader
}

func (e *ClientEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.upgrader.CheckOrigin == nil {
		e.init()
	}
	q := r.URL.Query()
	deviceID := q.Get("id")
	if deviceID == "" {
		http.Error(w, "missing device id", http.StatusBadRequest)
		return
	}

	device := e.Hub.Device(deviceID)
	if device == nil {
		http.Error(w, "device offline", http.StatusNotFound)
		return
	}

	userID, err := e.resolveUserID(r.Context(), q.Get("token"))
	if err != nil {
		e.Log.Warn("client wshandler: token invalid", "device_id", deviceID)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	ok, err := e.Devices.BelongsToUser(r.Context(), deviceID, userID)
	if err != nil || !ok {
		e.Log.Warn("client wshandler: device does not belong to user", "device_id", deviceID, "user_id", userID)
		http.Error(w, "device not found", http.StatusForbidden)
		return
	}

	oidcToken, err := e.Users.OIDCToken(r.Context(), userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusForbidden)
		return
	}

	conn, err := e.upgrader.Upgrade(w, r, nil)
	if err != nil {
		e.Log.Warn("client wshandler: upgrade failed", "device_id", deviceID, "error", err)
		return
	}

	base := newWSConn(e.Lifetime, conn, e.Options.SendBuffer, e.Options.WriteTimeout)
	base.start() // launch the writer goroutine — without it no frame ever leaves this connection

	clientID := uuid.NewString()
	roleQuery := q.Get("clientType")
	multiplex := roleQuery == RoleUser || roleQuery == RoleAgent
	role := ""
	if multiplex {
		role = NormalizeRole(roleQuery)
	}

	client := &ClientConn{
		wsConn:    base,
		DeviceID:  deviceID,
		UserID:    userID,
		OIDCToken: oidcToken,
		ClientID:  clientID,
		Role:      role,
		Multiplex: multiplex,
	}
	if replaced := e.Hub.AddClient(client); replaced != nil {
		e.Log.Info("client wshandler: replacing same-role connection",
			"device_id", deviceID, "role", role, "old_client_id", replaced.ClientID)
		replaced.Close()
	}
	e.Log.Info("client wshandler: user connected to device",
		"device_id", deviceID, "user_id", userID, "client_id", clientID, "multiplex", multiplex)

	defer func() {
		e.Hub.RemoveClient(client)
		e.Log.Info("client wshandler: connection closed", "device_id", deviceID, "client_id", clientID)
	}()

	// First frame: device metadata + minted client_id.
	if frame, err := deviceMetadataFrame(clientID, device.DeviceVersion); err == nil {
		_ = client.SendTo(frame)
	} else {
		e.Log.Error("client wshandler: marshal metadata failed", "error", err)
	}

	e.readPump(client, device)
}

// readPump consumes client frames: plain "ping", offer (enriched and
// forwarded to the device), and new-ice-candidate (forwarded with client_id).
func (e *ClientEndpoint) readPump(client *ClientConn, device *DeviceConn) {
	client.ws.SetReadLimit(e.Options.MaxMessageSize)
	for {
		_ = client.ws.SetReadDeadline(time.Now().Add(e.Options.ReadDeadline))
		_, payload, err := client.ws.ReadMessage()
		if err != nil {
			e.Log.Debug("client wshandler: read closed", "device_id", client.DeviceID, "error", err)
			client.Close()
			return
		}
		if string(payload) == "ping" {
			_ = client.SendTo(pongFrame)
			continue
		}

		var req offerRequest
		if err := json.Unmarshal(payload, &req); err != nil || req.Type == "" {
			e.Log.Warn("client wshandler: unparseable frame", "device_id", client.DeviceID)
			continue
		}
		switch req.Type {
		case TypeOffer:
			e.Log.Debug("client wshandler: received offer", "device_id", client.DeviceID, "sd_len", len(req.Data.SD))
			clientType := req.Data.ClientType
			if clientType == RoleUser || clientType == RoleAgent {
				if !client.Multiplex || client.Role != NormalizeRole(clientType) {
					if replaced := e.Hub.PromoteClientRole(client, clientType); replaced != nil && replaced != client {
						e.Log.Info("client wshandler: role promote replaced peer",
							"device_id", client.DeviceID, "role", clientType, "old_client_id", replaced.ClientID)
						replaced.Close()
					}
				}
			} else if clientType == "" {
				clientType = RoleUser
			}
			var iceCred []ICEServerCred
			if e.ICECredIssuer != nil {
				iceCred = e.ICECredIssuer()
			}
			frame, err := deviceOfferFrame(client.ClientID, DeviceOfferData{
				SD:         req.Data.SD,
				IP:         device.IP,
				ICEServers: e.ICEServers,
				OidcGoogle: client.OIDCToken,
				ClientType: clientType,
				ICECred:    iceCred,
			})
			if err != nil {
				e.Log.Error("client wshandler: marshal offer failed", "error", err)
				continue
			}
			if !e.Hub.SendToDevice(client.DeviceID, frame) {
				e.Log.Warn("client wshandler: device went away", "device_id", client.DeviceID)
				client.Close()
				return
			}
		case TypeNewICECandidate:
			// Stamp bound client_id; reject mismatched uplink id.
			if req.ClientID != "" && req.ClientID != client.ClientID {
				e.Log.Warn("client wshandler: rejecting ICE with mismatched client_id",
					"device_id", client.DeviceID, "got", req.ClientID, "want", client.ClientID)
				continue
			}
			out := stampClientID(payload, client.ClientID)
			if !e.Hub.SendToDevice(client.DeviceID, out) {
				e.Log.Warn("client wshandler: device went away", "device_id", client.DeviceID)
				client.Close()
				return
			}
		case TypeRequestKeyframe:
			// Keyframe recovery requests ride the same client_id stamping as
			// ICE so the device targets the requesting role's video sink.
			// Firmware without a handler ignores the frame harmlessly.
			if req.ClientID != "" && req.ClientID != client.ClientID {
				e.Log.Warn("client wshandler: rejecting keyframe request with mismatched client_id",
					"device_id", client.DeviceID, "got", req.ClientID, "want", client.ClientID)
				continue
			}
			out := stampClientID(payload, client.ClientID)
			if !e.Hub.SendToDevice(client.DeviceID, out) {
				e.Log.Warn("client wshandler: device went away", "device_id", client.DeviceID)
				client.Close()
				return
			}
		default:
			e.Log.Warn("client wshandler: unsupported message type", "type", req.Type)
		}
	}
}

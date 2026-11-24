package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"arkkvm.com/arkkvm-cloud/internal/auth"
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

// McpTokenResolver authenticates dedicated MCP Bearer credentials.
// Browser sessions use a separate Cookie-only path; neither falls back to the other.
// *auth.McpTokenService satisfies this interface.
type McpTokenResolver interface {
	Resolve(ctx context.Context, token string) (int64, error)
}

func (e *ClientEndpoint) init() {
	e.upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     e.allowedOrigin,
	}
}

// ClientEndpoint serves the browser signaling channel mounted at
// "/webrtc/signaling/client?id=<deviceId>". Credentials arrive via a protected
// browser cookie, an MCP Authorization header, never a URL credential.
// Handshake order
// mirrors the legacy ClientSocketHandlerInterceptor (doc 02 §2.2): device
// online -> session token valid -> device belongs to user -> user exists.
type ClientEndpoint struct {
	OnConnected func(userID int64, request *http.Request, lifetime context.Context)
	Hub         *Hub
	Tokens      *auth.TokenService
	McpTokens   McpTokenResolver // optional: enables the MCP credential
	Devices     ClientDeviceStore
	Users       ClientUserStore
	ICEServers  []string
	// ICECredIssuer optionally supplies credential-bearing ICE entries
	// (self-hosted/Cloudflare TURN) stamped into each offer frame's additive
	// iceServersCred field; legacy firmware ignores the field.
	ICECredIssuer     func() []ICEServerCred
	Options           Options
	Log               *slog.Logger
	Lifetime          context.Context
	AllowedReturnURLs []string

	upgrader websocket.Upgrader
	initOnce sync.Once
}

func (e *ClientEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.initOnce.Do(e.init)
	token, credentialKind, err := e.signalingHandshakeCredential(r)
	if err != nil {
		http.Error(w, "invalid signaling credentials", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	if credentialKind == signalingMcpCredential && q.Get("clientType") != RoleAgent {
		http.Error(w, "MCP requires agent role", http.StatusForbidden)
		return
	}
	if credentialKind == signalingSessionCredential && q.Get("clientType") != "" && q.Get("clientType") != RoleUser {
		http.Error(w, "browser requires user role", http.StatusForbidden)
		return
	}
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

	var userID int64
	authSource := "cookie"
	switch credentialKind {
	case signalingSessionCredential:
		userID, _, err = e.Tokens.Resolve(r.Context(), token)
	case signalingMcpCredential:
		authSource = "mcp_bearer"
		err = auth.ErrInvalidToken
		if e.McpTokens != nil {
			userID, err = e.McpTokens.Resolve(r.Context(), token)
		}

	}
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
	role := RoleUser
	if credentialKind == signalingMcpCredential {
		role = RoleAgent
	}
	multiplex := true

	client := &ClientConn{
		CredentialHash: credentialHash(token),
		deviceConn:     device,
		wsConn:         base,
		DeviceID:       deviceID,
		UserID:         userID,
		OIDCToken:      oidcToken,
		ClientID:       clientID,
		Role:           role,
		AuthMCP:        credentialKind == signalingMcpCredential,
		Multiplex:      multiplex,
	}
	if replaced := e.Hub.AddClient(client); replaced != nil {
		e.Log.Info("client wshandler: replacing same-role connection",
			"device_id", deviceID, "role", role, "old_client_id", replaced.ClientID)
		replaced.closeWithCode(4409)
	}
	if e.OnConnected != nil {
		e.OnConnected(userID, r, client.ctx)
	}
	e.Log.Info("client wshandler: user connected to device",
		"device_id", deviceID, "user_id", userID, "client_id", clientID, "multiplex", multiplex, "auth_source", authSource)

	defer func() {
		client.Close()
		// Target the original device connection, never a replacement generation.
		if device.SessionAuthLease && device.wsConn != nil {
			_ = device.SendTo(authorizationFrame("session_close", client.ClientID, 0))
		}
		e.Hub.RemoveClient(client)
		e.Log.Info("client wshandler: connection closed", "device_id", deviceID, "client_id", clientID)
	}()
	if !e.authorized(r.Context(), client, device, token) {
		client.wsConn.closeUnauthorized()
		return
	}
	go e.watchAuthorization(client, device, token)

	// First frame: device metadata + minted client_id.
	if frame, err := deviceMetadataFrame(clientID, device.DeviceVersion); err == nil {
		_ = client.SendTo(frame)
	} else {
		e.Log.Error("client wshandler: marshal metadata failed", "error", err)
	}

	e.readPump(client, device, token)
}

// readPump consumes client frames: plain "ping", offer (enriched and
// forwarded to the device), and new-ice-candidate (forwarded with client_id).
func (e *ClientEndpoint) readPump(client *ClientConn, device *DeviceConn, token string) {
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
			var expires int64
			if device.SessionAuthLease {
				expires = time.Now().Add(authorizationLeaseTTL).UnixMilli()
			}
			if !e.authorized(client.ctx, client, device, token) || client.ctx.Err() != nil {
				client.wsConn.closeUnauthorized()
				return
			}
			clientType := req.Data.ClientType
			if !client.AuthMCP && clientType != "" && clientType != RoleUser {
				client.closeWithCode(4403)
				return
			}
			if client.AuthMCP && clientType != "" && clientType != RoleAgent {
				client.Close()
				return
			}
			if client.AuthMCP {
				clientType = RoleAgent
			}
			if clientType == RoleUser || clientType == RoleAgent {
				if !client.Multiplex || client.Role != NormalizeRole(clientType) {
					if replaced := e.Hub.PromoteClientRole(client, clientType); replaced != nil && replaced != client {
						e.Log.Info("client wshandler: role promote replaced peer",
							"device_id", client.DeviceID, "role", clientType, "old_client_id", replaced.ClientID)
						replaced.closeWithCode(4409)
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
				AuthorizationExpiresAt: expires,
				SD:                     req.Data.SD,
				IP:                     device.IP,
				ICEServers:             e.ICEServers,
				OidcGoogle:             client.OIDCToken,
				ClientType:             clientType,
				ICECred:                iceCred,
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

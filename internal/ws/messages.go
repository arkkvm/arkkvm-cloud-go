package ws

import "encoding/json"

// Message type constants exchanged on both channels (protocol strings are
// case-sensitive and must never drift from the legacy values).
const (
	TypePing            = "ping"              // plain-text application heartbeat (not JSON)
	TypeDeviceMetadata  = "device-metadata"   // cloud -> client, first frame after connect
	TypeOffer           = "offer"             // client -> cloud -> device
	TypeAnswer          = "answer"            // device -> cloud -> client
	TypeNewICECandidate = "new-ice-candidate" // both directions, forwarded verbatim
	TypeRequestKeyframe = "request-keyframe"  // client -> cloud -> device; stamped like ICE
	TypeError           = "error"             // device -> cloud -> client (e.g. agentSlotOccupied)
)

// heartbeatPing is the server->device heartbeat frame sent every 60s. This is
// the FIXED version of the legacy frame: valid JSON, aligned with the message
// envelope (migration decision, doc 05 §3.2 — the legacy `{ type: "ping" }`
// with unquoted keys was a bug, not a protocol).
var heartbeatPing = []byte(`{"type":"ping"}`)

var pongFrame = []byte("pong")

// DeviceMetadataData is the payload of the first frame pushed to a client.
type DeviceMetadataData struct {
	DeviceVersion string `json:"deviceVersion"`
}

// deviceMetadataFrame builds the first client frame with a minted client_id.
func deviceMetadataFrame(clientID, deviceVersion string) ([]byte, error) {
	return json.Marshal(struct {
		Type     string             `json:"type"`
		ClientID string             `json:"client_id,omitempty"`
		Data     DeviceMetadataData `json:"data"`
	}{TypeDeviceMetadata, clientID, DeviceMetadataData{DeviceVersion: deviceVersion}})
}

// ICEServerCred is one credential-bearing ICE entry for the additive
// iceServersCred offer-frame field. Legacy firmware serde-ignores the field;
// firmware that reads it prefers these entries over the bare iceServers url
// list — TURN needs per-session credentials a plain url list cannot carry.
type ICEServerCred struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// DeviceOfferData is the payload the cloud forwards to the device when a
// client sends an offer. Field names are protocol: the Google token field is
// "oidcGoogle" — the legacy Java field was named OidcGoogle, but Lombok's
// getter getOidcGoogle made Jackson decapitalize it to "oidcGoogle" on the
// wire (confirmed against the web console bundle), and the device firmware
// reads the lowercase form.
type DeviceOfferData struct {
	AuthorizationExpiresAt int64           `json:"authorizationExpiresAt,omitempty"`
	SD                     string          `json:"sd"`
	IP                     string          `json:"ip"`
	ICEServers             []string        `json:"iceServers"`
	OidcGoogle             string          `json:"oidcGoogle"`
	ClientType             string          `json:"clientType,omitempty"`
	ICECred                []ICEServerCred `json:"iceServersCred,omitempty"`
}

// deviceOfferFrame builds {"type":"offer","client_id":...,"data":{...}}.
func deviceOfferFrame(clientID string, data DeviceOfferData) ([]byte, error) {
	return json.Marshal(struct {
		Type     string          `json:"type"`
		ClientID string          `json:"client_id,omitempty"`
		Data     DeviceOfferData `json:"data"`
	}{TypeOffer, clientID, data})
}

// messageHeader peeks at type and optional client_id for demux.
type messageHeader struct {
	Type     string `json:"type"`
	ClientID string `json:"client_id"`
}

func messageType(payload []byte) string {
	var head messageHeader
	if err := json.Unmarshal(payload, &head); err != nil {
		return ""
	}
	return head.Type
}

func frameClientID(payload []byte) string {
	var head messageHeader
	if err := json.Unmarshal(payload, &head); err != nil {
		return ""
	}
	return head.ClientID
}

// forwardableDeviceTypes are device→client frames the cloud relays.
func forwardableDeviceType(t string) bool {
	switch t {
	case TypeAnswer, TypeNewICECandidate, TypeError:
		return true
	default:
		return false
	}
}

// stampClientID sets top-level client_id on a JSON object frame (best-effort).
func stampClientID(payload []byte, clientID string) []byte {
	if clientID == "" {
		return payload
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return payload
	}
	raw, err := json.Marshal(clientID)
	if err != nil {
		return payload
	}
	obj["client_id"] = raw
	out, err := json.Marshal(obj)
	if err != nil {
		return payload
	}
	return out
}

// offerRequest is the shape a client sends: {"type":"offer","data":{"sd":...,"clientType":...}}.
type offerRequest struct {
	Type     string `json:"type"`
	ClientID string `json:"client_id"`
	Data     struct {
		SD         string `json:"sd"`
		ClientType string `json:"clientType"`
	} `json:"data"`
}

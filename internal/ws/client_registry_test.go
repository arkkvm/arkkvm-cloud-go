package ws

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func testConn(deviceID, clientID, role string) *ClientConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &ClientConn{
		wsConn: &wsConn{
			send:         make(chan []byte, 32),
			ctx:          ctx,
			cancel:       cancel,
			writeTimeout: time.Second,
		},
		DeviceID: deviceID,
		ClientID: clientID,
		Role:     role,
	}
}

func TestClientRegistryLegacyOverwrite(t *testing.T) {
	r := newClientRegistry()
	a := testConn("dev1", "ca", "")
	b := testConn("dev1", "cb", "")
	r.Add(a, false)
	r.Add(b, false)
	if got := r.Legacy("dev1"); got != b {
		t.Fatalf("legacy want b, got %v", got)
	}
	if r.ByClientID("ca") != a {
		t.Fatal("a should remain in byClientID until removed")
	}
	if r.ByClientID("cb") != b {
		t.Fatal("b missing from byClientID")
	}
}

func TestClientRegistryDualRole(t *testing.T) {
	r := newClientRegistry()
	user := testConn("dev1", "cu", RoleUser)
	user.Multiplex = true
	agent := testConn("dev1", "ca", RoleAgent)
	agent.Multiplex = true
	r.Add(user, true)
	r.Add(agent, true)
	if r.ByClientID("cu") != user || r.ByClientID("ca") != agent {
		t.Fatal("both roles should be indexed by client_id")
	}
	if r.Legacy("dev1") != agent {
		t.Fatal("legacy is last writer (agent)")
	}
}

func TestClientRegistrySameRoleReplace(t *testing.T) {
	r := newClientRegistry()
	first := testConn("dev1", "c1", RoleUser)
	first.Multiplex = true
	second := testConn("dev1", "c2", RoleUser)
	second.Multiplex = true
	r.Add(first, true)
	replaced := r.Add(second, true)
	if replaced != first {
		t.Fatalf("want first replaced, got %v", replaced)
	}
	if r.ByClientID("c1") != nil {
		t.Fatal("old client_id should be cleared")
	}
	if r.ByClientID("c2") != second {
		t.Fatal("new client_id missing")
	}
}

func TestClientRegistryRemoveSelfCheck(t *testing.T) {
	r := newClientRegistry()
	a := testConn("dev1", "ca", RoleUser)
	a.Multiplex = true
	b := testConn("dev1", "cb", RoleUser)
	b.Multiplex = true
	r.Add(a, true)
	r.Add(b, true)
	r.Remove(a) // a already replaced; should not clear b
	if r.ByClientID("cb") != b {
		t.Fatal("removing stale a must not drop b")
	}
	if r.Legacy("dev1") != b {
		t.Fatal("legacy should still be b")
	}
	r.Remove(b)
	if r.HasClient("dev1") {
		t.Fatal("expected empty after remove b")
	}
}

func TestResolveDelivery(t *testing.T) {
	r := newClientRegistry()
	user := testConn("dev1", "cu", RoleUser)
	user.Multiplex = true
	agent := testConn("dev1", "ca", RoleAgent)
	agent.Multiplex = true
	r.Add(user, true)
	r.Add(agent, true)

	if r.ResolveDelivery("dev1", "cu") != user {
		t.Fatal("demux by client_id user")
	}
	if r.ResolveDelivery("dev1", "ca") != agent {
		t.Fatal("demux by client_id agent")
	}
	if r.ResolveDelivery("dev1", "") != agent {
		t.Fatal("empty client_id falls back to legacy (last writer)")
	}
	if r.ResolveDelivery("dev1", "unknown") != agent {
		t.Fatal("unknown client_id falls back to legacy")
	}
}

func TestHubDispatchDemuxAndWhitelist(t *testing.T) {
	h := NewHub(nil, nil)
	user := testConn("dev1", "cu", RoleUser)
	user.Multiplex = true
	agent := testConn("dev1", "ca", RoleAgent)
	agent.Multiplex = true
	h.AddClient(user)
	h.AddClient(agent)

	ansUser, _ := json.Marshal(map[string]any{
		"type": TypeAnswer, "client_id": "cu", "data": "sdp-u",
	})
	h.DispatchDeviceMessage("dev1", ansUser)
	select {
	case got := <-user.send:
		if string(got) != string(ansUser) {
			t.Fatalf("user got %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("user expected answer")
	}
	select {
	case <-agent.send:
		t.Fatal("agent must not receive user answer")
	default:
	}

	errFrame, _ := json.Marshal(map[string]any{
		"type": TypeError, "client_id": "ca",
		"data": map[string]string{"code": "agentSlotOccupied"},
	})
	h.DispatchDeviceMessage("dev1", errFrame)
	select {
	case got := <-agent.send:
		if string(got) != string(errFrame) {
			t.Fatalf("agent got %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("agent expected error")
	}

	pong, _ := json.Marshal(map[string]any{"type": "pong"})
	h.DispatchDeviceMessage("dev1", pong)
	select {
	case <-user.send:
		t.Fatal("pong must not be forwarded")
	case <-agent.send:
		t.Fatal("pong must not be forwarded")
	default:
	}

	// No client_id → legacy (agent last writer)
	ansLegacy, _ := json.Marshal(map[string]any{"type": TypeAnswer, "data": "sdp"})
	h.DispatchDeviceMessage("dev1", ansLegacy)
	select {
	case <-agent.send:
	case <-time.After(time.Second):
		t.Fatal("legacy delivery to last writer")
	}
}

func TestMessagesMetadataAndOffer(t *testing.T) {
	meta, err := deviceMetadataFrame("cid-1", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != TypeDeviceMetadata || m["client_id"] != "cid-1" {
		t.Fatalf("metadata frame: %v", m)
	}

	offer, err := deviceOfferFrame("cid-1", DeviceOfferData{
		SD: "sdp", ClientType: RoleAgent, IP: "1.1.1.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	var o map[string]any
	if err := json.Unmarshal(offer, &o); err != nil {
		t.Fatal(err)
	}
	if o["client_id"] != "cid-1" {
		t.Fatalf("offer client_id: %v", o)
	}
	data := o["data"].(map[string]any)
	if data["clientType"] != RoleAgent || data["sd"] != "sdp" {
		t.Fatalf("offer data: %v", data)
	}

	stamped := stampClientID([]byte(`{"type":"new-ice-candidate","data":{}}`), "cid-9")
	if frameClientID(stamped) != "cid-9" {
		t.Fatalf("stamp failed: %s", stamped)
	}
}

func TestPromoteMultiplex(t *testing.T) {
	r := newClientRegistry()
	c := testConn("dev1", "c1", "")
	r.Add(c, false)
	r.PromoteMultiplex(c, RoleAgent)
	if !c.Multiplex || c.Role != RoleAgent {
		t.Fatal("promote flags")
	}
	if r.ByClientID("c1") != c {
		t.Fatal("still indexed")
	}
}

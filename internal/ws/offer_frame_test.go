package ws

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeviceOfferFrameCarriesCredentialedICE(t *testing.T) {
	frame, err := deviceOfferFrame("cid-1", DeviceOfferData{
		SD: "v=0",
		ICECred: []ICEServerCred{{
			URLs:       []string{"turn:stun.arkkvm.cn:3478?transport=udp"},
			Username:   "1791979895",
			Credential: "c2VjcmV0",
		}},
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var out struct {
		Data struct {
			ICECred []ICEServerCred `json:"iceServersCred"`
		} `json:"data"`
	}
	if err := json.Unmarshal(frame, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(out.Data.ICECred) != 1 ||
		out.Data.ICECred[0].Username != "1791979895" ||
		len(out.Data.ICECred[0].URLs) != 1 {
		t.Fatalf("iceServersCred round-trip mismatch: %+v", out.Data.ICECred)
	}
}

func TestDeviceOfferFrameOmitsEmptyCred(t *testing.T) {
	// Legacy wire bytes must stay unchanged when no credential issuer is
	// wired: omitempty keeps the field off the wire entirely.
	frame, err := deviceOfferFrame("", DeviceOfferData{SD: "v=0"})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(frame), "iceServersCred") {
		t.Fatalf("empty issuer must not emit iceServersCred: %s", frame)
	}
}

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
	"github.com/arkkvm/arkkvm-cloud-go/internal/ws"
)

// fakeHub records interactions with the signaling hub. AcquirePending returns
// a real *ws.PendingWaiter only when a real hub is attached; by default the
// "acquire" path is not expected to be reached in rejection tests.
type fakeHub struct {
	online    map[string]bool
	acquireOK bool
	sent      []string // device IDs that received a frame
}

func (f *fakeHub) IsOnline(deviceID string) bool { return f.online[deviceID] }

func (f *fakeHub) AcquirePending(deviceID string) (*ws.PendingWaiter, bool) {
	return nil, false
}

func (f *fakeHub) SendToDevice(deviceID string, payload []byte) bool {
	f.sent = append(f.sent, deviceID)
	return true
}

type fakeOwner struct {
	ownerOf map[string]int64 // deviceID -> owning userID
	err     error
}

func (f *fakeOwner) BelongsToUser(_ context.Context, deviceID string, userID int64) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.ownerOf[deviceID] == userID, nil
}

func newWebrtcTestRouter(hub webrtcHub, owner deviceOwnership, userID int64) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &WebrtcHandler{hub: hub, owner: owner, waitTimeout: 0}
	authed := r.Group("/", func(c *gin.Context) { c.Set("auth.userID", userID); c.Next() })
	authed.POST("/webrtc/session", h.CreateSession)
	return r
}

func postSession(r *gin.Engine, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webrtc/session", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func baseResultMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var br struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Code    int    `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &br); err != nil {
		t.Fatalf("response not BaseResult: %v (%s)", err, w.Body.String())
	}
	return br.Message
}

// F1: a logged-in user must not be able to open a session on a device owned
// by someone else — the device-side offer validation is dead code (F2), so
// this handler check is the only authorization gate.
func TestCreateSessionRejectsNonOwner(t *testing.T) {
	hub := &fakeHub{online: map[string]bool{"dev-1": true}}
	owner := &fakeOwner{ownerOf: map[string]int64{"dev-1": 42}}
	r := newWebrtcTestRouter(hub, owner, 7) // user 7 does not own dev-1

	w := postSession(r, `{"id":"dev-1","sd":"v=0..."}`)
	if w.Code != http.StatusOK {
		t.Fatalf("business failure rides on HTTP 200, got %d", w.Code)
	}
	if msg := baseResultMessage(t, w); msg != "device not found" {
		t.Fatalf("want 'device not found' (no existence leak), got %q", msg)
	}
	if len(hub.sent) != 0 {
		t.Fatalf("offer must not reach the device for a non-owner, sent=%v", hub.sent)
	}
}

func TestCreateSessionRejectsOwnerLookupError(t *testing.T) {
	hub := &fakeHub{online: map[string]bool{"dev-1": true}}
	owner := &fakeOwner{err: context.DeadlineExceeded}
	r := newWebrtcTestRouter(hub, owner, 42)

	w := postSession(r, `{"id":"dev-1","sd":"v=0..."}`)
	if msg := baseResultMessage(t, w); msg != "device not found" {
		t.Fatalf("want 'device not found', got %q", msg)
	}
	if len(hub.sent) != 0 {
		t.Fatalf("offer must not reach the device, sent=%v", hub.sent)
	}
}

// The ownership gate must not regress the pre-existing online check, and a
// legitimate owner proceeds to the offer dispatch (the wait then times out
// with the injected zero timeout).
func TestCreateSessionOwnerProceedsToOffer(t *testing.T) {
	hub := &fakeHub{online: map[string]bool{"dev-1": true}}
	owner := &fakeOwner{ownerOf: map[string]int64{"dev-1": 42}}
	r := newWebrtcTestRouter(hub, owner, 42)

	w := postSession(r, `{"id":"dev-1","sd":"v=0..."}`)
	// AcquirePending on the fake returns false -> "device is busy" is fine;
	// the point is the request got past the ownership gate. Wire a real hub
	// for the full path, which the fake cannot provide — assert the gate
	// passed by checking we did NOT answer "device not found".
	msg := baseResultMessage(t, w)
	if msg == "device not found" {
		t.Fatal("owner must pass the ownership gate")
	}
}

func TestCreateSessionOfflineDeviceUnchanged(t *testing.T) {
	hub := &fakeHub{online: map[string]bool{}}
	owner := &fakeOwner{ownerOf: map[string]int64{}}
	r := newWebrtcTestRouter(hub, owner, 42)

	w := postSession(r, `{"id":"dev-x","sd":"v=0..."}`)
	if msg := baseResultMessage(t, w); msg != "device not found" {
		t.Fatalf("want 'device not found', got %q", msg)
	}
	if len(hub.sent) != 0 {
		t.Fatalf("no dispatch expected, sent=%v", hub.sent)
	}
}

// compile-time check that the interfaces match the production types.
var (
	_ webrtcHub       = (*ws.Hub)(nil)
	_ deviceOwnership = (*service.DeviceService)(nil)
)

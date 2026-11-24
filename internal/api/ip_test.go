package api

import (
	"net/http/httptest"
	"testing"

	"arkkvm.com/arkkvm-cloud/internal/api/handler"
)

func TestIPRouteIsPublic(t *testing.T) {
	ip, err := handler.NewIPHandler(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(Deps{
		IP:      ip,
		OAuth:   &handler.OAuthHandler{},
		Release: &handler.ReleaseHandler{},
		Devices: &handler.DeviceHandler{},
		Mcp:     &handler.McpHandler{},
		Users:   &handler.UserHandler{},
		Webrtc:  &handler.WebrtcHandler{},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ip", nil)
	r.RemoteAddr = "8.8.8.8:123"
	router.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("public endpoint returned %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
}

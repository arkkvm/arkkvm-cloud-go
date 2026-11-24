package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Retirement must fail closed for owners, non-owners and malformed requests;
// there is deliberately no hub/device dependency to dispatch an unleased offer.
func TestRetiredHTTPCreateSessionCannotOpenDeviceSessions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, userID := range []int64{0, 7, 42} {
		for _, body := range []string{`{"id":"dev-1","sd":"v=0"}`, `{}`, `invalid`} {
			r := gin.New()
			h := NewWebrtcHandler(nil, nil)
			r.POST("/webrtc/session", func(c *gin.Context) { c.Set("auth.userID", userID); h.CreateSession(c) })
			w := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/webrtc/session", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, request)
			if w.Code != http.StatusGone {
				t.Fatalf("retired path accepted user %d: %d", userID, w.Code)
			}
		}
	}
}

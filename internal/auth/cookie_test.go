package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	return c, w
}

func cookieValue(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	resp := &http.Response{Header: w.Header()}
	for _, ck := range resp.Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

func TestCookieRoundTrip(t *testing.T) {
	m := NewCookieManager("arkcookie", 86400, false)
	c, w := newTestContext()

	m.Set(c, "returnTo", "https://app.example.com/console?x=1")
	ck := cookieValue(t, w, "returnTo")
	if ck == nil {
		t.Fatal("cookie not set")
	}
	if ck.MaxAge != 86400 || !ck.HttpOnly || ck.Path != "/" {
		t.Fatalf("unexpected cookie attributes: %+v", ck)
	}

	// Read back through a fresh request carrying the same cookie.
	c2, _ := newTestContext()
	c2.Request.AddCookie(ck)
	if got := m.Get(c2, "returnTo"); got != "https://app.example.com/console?x=1" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestCookieTamperDetection(t *testing.T) {
	m := NewCookieManager("arkcookie", 86400, false)
	c, w := newTestContext()
	m.Set(c, "deviceId", "ark-0001")
	ck := cookieValue(t, w, "deviceId")
	if ck == nil {
		t.Fatal("cookie not set")
	}

	// Tamper with the value, keep the signature.
	forged := *ck
	idx := -1
	for i := 0; i < len(forged.Value); i++ {
		if forged.Value[i] == '.' {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("no signature separator found")
	}
	forged.Value = "ark-9999" + forged.Value[idx:]

	c2, _ := newTestContext()
	c2.Request.AddCookie(&forged)
	if got := m.Get(c2, "deviceId"); got != "" {
		t.Fatalf("tampered cookie must not verify, got %q", got)
	}
}

func TestCookieWrongKeyRejects(t *testing.T) {
	m1 := NewCookieManager("arkcookie", 86400, false)
	m2 := NewCookieManager("other-key", 86400, false)
	c, w := newTestContext()
	m1.Set(c, "returnTo", "https://x.example.com")
	ck := cookieValue(t, w, "returnTo")

	c2, _ := newTestContext()
	c2.Request.AddCookie(ck)
	if got := m2.Get(c2, "returnTo"); got != "" {
		t.Fatalf("cookie signed with a different key must not verify, got %q", got)
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", ""},  // prefix is case-sensitive, matching legacy startsWith
		{"Bearer", ""},
		{"", ""},
		{"Basic xyz", ""},
	}
	for _, tc := range cases {
		if got := BearerToken(tc.in); got != tc.want {
			t.Errorf("BearerToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func cookieHeaderSecure(t *testing.T, secure bool) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	NewCookieManager("k", 600, secure).Set(c, "returnTo", "https://app.example/")
	cookie := w.Header().Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("no Set-Cookie header")
	}
	return cookie
}

func TestSetCookieSameSiteNoneWhenSecure(t *testing.T) {
	cookie := cookieHeaderSecure(t, true)
	// Apple's form_post callback is a cross-site POST: without SameSite=None
	// the browser drops the OAuth cookies before the callback reads them.
	if !strings.Contains(cookie, "SameSite=None") {
		t.Fatalf("secure cookie missing SameSite=None: %s", cookie)
	}
	if !strings.Contains(cookie, " Secure") {
		t.Fatalf("SameSite=None cookie missing Secure: %s", cookie)
	}
}

func TestSetCookieLaxWhenInsecure(t *testing.T) {
	cookie := cookieHeaderSecure(t, false)
	if !strings.Contains(cookie, "SameSite=Lax") {
		t.Fatalf("insecure cookie missing SameSite=Lax: %s", cookie)
	}
	if strings.Contains(cookie, "SameSite=None") {
		t.Fatalf("insecure cookie must not use SameSite=None (browsers reject None without Secure): %s", cookie)
	}
}

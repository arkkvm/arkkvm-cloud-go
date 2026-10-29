package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

// CookieManager reproduces the legacy SecureCookieUtil byte-for-byte:
//
//	stored value = url.QueryEscape(v) + "." + base64.StdEncoding(HMAC-SHA256(key, v))
//
// The HMAC is computed over the RAW value; URL escaping applies only to the
// stored segment. Verification uses a constant-time comparison (hmac.Equal,
// equivalent to MessageDigest.isEqual in the Java version).
type CookieManager struct {
	signingKey []byte
	maxAge     int
	secure     bool
}

func NewCookieManager(signingKey string, maxAge int, secure bool) *CookieManager {
	if maxAge <= 0 {
		maxAge = 86400
	}
	return &CookieManager{signingKey: []byte(signingKey), maxAge: maxAge, secure: secure}
}

func (m *CookieManager) hmacOf(value string) string {
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Set writes a signed cookie (Path=/, HttpOnly, MaxAge from config).
func (m *CookieManager) Set(c *gin.Context, name, value string) {
	m.set(c, name, value, m.maxAge)
}

// SetWithMaxAge writes a signed cookie with an explicit Max-Age (same
// signature format); used for short-lived values such as the OAuth state.
func (m *CookieManager) SetWithMaxAge(c *gin.Context, name, value string, maxAge int) {
	if maxAge <= 0 {
		maxAge = m.maxAge
	}
	m.set(c, name, value, maxAge)
}

func (m *CookieManager) set(c *gin.Context, name, value string, maxAge int) {
	if name == "" || value == "" {
		return
	}
	// SameSite policy: these cookies must survive the OAuth round trip.
	// GET redirects (Google/GitHub/Microsoft) carry Lax cookies on the
	// top-level navigation, but Apple's response_mode=form_post is a
	// cross-site POST — SameSite=None is required there, and browsers only
	// accept None together with Secure (every deployment fronts TLS).
	sameSite := http.SameSiteLaxMode
	if m.secure {
		sameSite = http.SameSiteNoneMode
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value) + "." + m.hmacOf(value),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: sameSite,
		MaxAge:   maxAge,
	})
}

// Get reads and verifies a signed cookie; returns "" when absent or invalid.
func (m *CookieManager) Get(c *gin.Context, name string) string {
	cookie, err := c.Request.Cookie(name)
	if err != nil || cookie.Value == "" {
		return ""
	}
	lastDot := -1
	for i := len(cookie.Value) - 1; i >= 0; i-- {
		if cookie.Value[i] == '.' {
			lastDot = i
			break
		}
	}
	if lastDot <= 0 {
		return ""
	}
	encoded, signature := cookie.Value[:lastDot], cookie.Value[lastDot+1:]
	raw, err := url.QueryUnescape(encoded)
	if err != nil {
		return ""
	}
	if !hmac.Equal([]byte(signature), []byte(m.hmacOf(raw))) {
		return ""
	}
	return raw
}

// Clear expires a cookie immediately (Path=/, HttpOnly).
func (m *CookieManager) Clear(c *gin.Context, name string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

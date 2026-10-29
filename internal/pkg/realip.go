package pkg

import (
	"net/http"
	"strings"
)

// RealIP resolves the client IP the same way the legacy handshake interceptor
// intended, with two improvements over the Java code: both the
// RFC 7239 Forwarded header and X-Forwarded-For are honored, and quotes or a
// port suffix around the address are stripped.
// Precedence: Forwarded "for=" > first X-Forwarded-For entry > RemoteAddr.
func RealIP(r *http.Request) string {
	if f := r.Header.Get("Forwarded"); f != "" {
		if ip := firstForwardedFor(f); ip != "" {
			return ip
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := cleanIP(parts[0]); ip != "" {
			return ip
		}
	}
	if r.RemoteAddr != "" {
		// RemoteAddr is host:port; the port is not always present.
		if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > 0 {
			return strings.Trim(r.RemoteAddr[:idx], "[]")
		}
		return r.RemoteAddr
	}
	return ""
}

// firstForwardedFor extracts the first for= entry, e.g. `for=1.2.3.4;proto=http`.
func firstForwardedFor(forwarded string) string {
	for _, elem := range strings.Split(forwarded, ";") {
		elem = strings.TrimSpace(elem)
		if strings.HasPrefix(strings.ToLower(elem), "for=") {
			return cleanIP(elem[4:])
		}
	}
	return ""
}

// cleanIP strips surrounding quotes, brackets and an optional :port suffix.
func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	if idx := strings.LastIndex(s, ":"); idx > 0 && !strings.Contains(s[idx+1:], ":") {
		// Keep the last colon only when it looks like a port (IPv6 has multiple colons).
		s = s[:idx]
	}
	return strings.Trim(s, "[]")
}

package pkg

import "net/http"

// RealIP accepts forwarding headers only from a configured immediate proxy.
// Forwarded is intentionally ignored: use the right-to-left XFF chain that
// Nginx appends to, rather than client-controlled leftmost values.
func RealIP(r *http.Request, policies ...*TrustedProxies) string {
	var policy *TrustedProxies
	if len(policies) == 1 {
		policy = policies[0]
	}
	ip := policy.ClientIP(r)
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

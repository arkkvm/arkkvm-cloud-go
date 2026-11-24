package pkg

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIP(t *testing.T) {
	cases := []struct {
		name      string
		forwarded string
		xff       string
		remote    string
		want      string
	}{
		{"Forwarded plain", "for=1.2.3.4;proto=http;host=x", "", "9.9.9.9:1234", "9.9.9.9"},
		{"Forwarded last", "host=a;for=5.6.7.8", "", "9.9.9.9:1234", "9.9.9.9"},
		{"Forwarded quoted+port", `for="3.4.5.6:5678"`, "", "9.9.9.9:1234", "9.9.9.9"},
		{"XFF first of list", "", "1.1.1.1, 2.2.2.2", "9.9.9.9:1234", "9.9.9.9"},
		{"fallback remote", "", "", "10.0.0.1:5555", "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.forwarded != "" {
				r.Header.Set("Forwarded", tc.forwarded)
			}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			// Without a configured proxy, even well-formed forwarding headers are untrusted.
			if got := RealIP(r); got != tc.want {
				t.Errorf("RealIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	policy, err := NewTrustedProxies([]string{"10.0.0.1/32", "2001:db8::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, remote, xff, real, want string }{
		{"trusted nginx", "10.0.0.1:123", "203.0.113.8", "", "203.0.113.8"},
		{"spoofed prefix", "10.0.0.1:123", "1.1.1.1, 203.0.113.8", "", "203.0.113.8"},
		{"trusted chain", "10.0.0.1:123", "1.1.1.1, 203.0.113.8, 10.0.0.1", "", "203.0.113.8"},
		{"untrusted peer", "203.0.113.8:123", "1.1.1.1", "1.1.1.1", "203.0.113.8"},
		{"invalid xff", "10.0.0.1:123", "invalid", "1.1.1.1", "10.0.0.1"},
		{"real ip", "10.0.0.1:123", "", "203.0.113.8", "203.0.113.8"},
		{"ipv6", "[2001:db8::1]:123", "2001:db8::8", "", "2001:db8::8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("X-Forwarded-For", tc.xff)
			r.Header.Set("X-Real-IP", tc.real)
			r.Header.Set("Forwarded", "for=1.1.1.1")
			if got := RealIP(r, policy); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	if _, err := NewTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid proxy accepted")
	}
}

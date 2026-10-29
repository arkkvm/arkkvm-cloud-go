package pkg

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIP(t *testing.T) {
	cases := []struct {
		name    string
		forwarded string
		xff     string
		remote  string
		want    string
	}{
		{"Forwarded plain", "for=1.2.3.4;proto=http;host=x", "", "9.9.9.9:1234", "1.2.3.4"},
		{"Forwarded last", "host=a;for=5.6.7.8", "", "9.9.9.9:1234", "5.6.7.8"},
		{"Forwarded quoted+port", `for="3.4.5.6:5678"`, "", "9.9.9.9:1234", "3.4.5.6"},
		{"XFF first of list", "", "1.1.1.1, 2.2.2.2", "9.9.9.9:1234", "1.1.1.1"},
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
			if got := RealIP(r); got != tc.want {
				t.Errorf("RealIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

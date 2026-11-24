package handler

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/netip"
	"testing"

	"arkkvm.com/arkkvm-cloud/internal/service"
	"github.com/gin-gonic/gin"
)

type stubIPLocator struct {
	called bool
	err    error
}

func (s *stubIPLocator) Lookup(ip netip.Addr) (service.IPLocation, error) {
	s.called = true
	code := "CN"
	return service.IPLocation{CountryCode: &code}, s.err
}

func TestIPClientAddress(t *testing.T) {
	for _, tc := range []struct {
		name, peer, xff, realIP, want string
		trusted                       []string
	}{
		{name: "direct", peer: "8.8.8.8:123", want: "8.8.8.8"},
		{name: "untrusted spoof", peer: "8.8.8.8:123", xff: "1.1.1.1", realIP: "9.9.9.9", want: "8.8.8.8"},
		{name: "trusted proxy", peer: "127.0.0.1:123", xff: "1.1.1.1", trusted: []string{"127.0.0.1"}, want: "1.1.1.1"},
		{name: "multiple proxies with spoofed left value", peer: "10.0.0.2:123", xff: "9.9.9.9, 1.1.1.1, 10.0.0.1", trusted: []string{"10.0.0.0/24"}, want: "1.1.1.1"},
		{name: "invalid forwarded IP", peer: "127.0.0.1:123", xff: "invalid", trusted: []string{"127.0.0.1"}, want: "127.0.0.1"},
		{name: "real IP", peer: "127.0.0.1:123", realIP: "1.1.1.1", trusted: []string{"127.0.0.1"}, want: "1.1.1.1"},
		{name: "IPv6 direct", peer: "[2606:4700:4700::1111]:123", want: "2606:4700:4700::1111"},
		{name: "IPv6 forwarded", peer: "[::1]:123", xff: "2606:4700:4700::1111", trusted: []string{"::1"}, want: "2606:4700:4700::1111"},
		{name: "mapped IPv4", peer: "[::ffff:8.8.8.8]:123", want: "8.8.8.8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := NewIPHandler(nil, tc.trusted)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/ip", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.xff)
			r.Header.Set("X-Real-IP", tc.realIP)
			if got := h.clientIP(r).String(); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
	if _, err := NewIPHandler(nil, []string{"invalid"}); err == nil {
		t.Fatal("invalid proxy accepted")
	}
}

func TestIPResponseAndGracefulFailure(t *testing.T) {
	for _, tc := range []struct {
		name, peer              string
		err                     error
		wantLookup, wantCountry bool
	}{
		{"public", "8.8.8.8:80", nil, true, true},
		{"private", "192.168.1.2:80", nil, false, false},
		{"loopback", "[::1]:80", nil, false, false},
		{"lookup failure", "8.8.8.8:80", errors.New("unavailable"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := &stubIPLocator{err: tc.err}
			h, err := NewIPHandler(lookup, nil)
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.GET("/ip", h.Get)
			r := httptest.NewRequest("GET", "/ip", nil)
			r.RemoteAddr = tc.peer
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			var result struct {
				Success bool
				Data    struct {
					IP          string
					CountryCode *string
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || !result.Success || result.Data.IP == "" {
				t.Fatalf("unexpected response: %s", w.Body.String())
			}
			if lookup.called != tc.wantLookup || (result.Data.CountryCode != nil) != tc.wantCountry {
				t.Fatalf("unexpected lookup: %s", w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

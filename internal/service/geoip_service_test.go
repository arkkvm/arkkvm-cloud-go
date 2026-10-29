package service

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGeoIPParsing(t *testing.T) {
	loc := parseIPLocation("中国|广东省|深圳市|电信|CN")
	if loc.CountryCode == nil || *loc.CountryCode != "CN" || loc.Region == nil || *loc.Region != "广东省" || loc.City == nil || *loc.City != "深圳市" {
		t.Fatalf("unexpected location: %+v", loc)
	}
	loc = parseIPLocation("United States|0|0|0|US")
	if loc.CountryCode == nil || *loc.CountryCode != "US" || loc.Region != nil || loc.City != nil {
		t.Fatalf("unexpected zero fields: %+v", loc)
	}
	for _, raw := range []string{"", "malformed", "中国|0|广东省|深圳市|电信"} {
		if got := parseIPLocation(raw); got.Country != nil || got.CountryCode != nil {
			t.Fatalf("invalid format accepted: %q", raw)
		}
	}
}

func TestGeoIPUnavailable(t *testing.T) {
	s, err := NewGeoIPService("", "")
	if err != nil {
		t.Fatal(err)
	}
	if loc, err := s.Lookup(netip.MustParseAddr("8.8.8.8")); err != nil || loc.Country != nil {
		t.Fatalf("unexpected unavailable result: %+v %v", loc, err)
	}
	s, err = NewGeoIPService(filepath.Join(t.TempDir(), "missing.xdb"), "")
	if err == nil || s == nil {
		t.Fatal("missing database must return a usable fallback and error")
	}
	bad := filepath.Join(t.TempDir(), "bad.xdb")
	if err := os.WriteFile(bad, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGeoIPService(bad, ""); err == nil {
		t.Fatal("invalid database accepted")
	}
}

func TestPublicIP(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "192.168.1.1", "10.0.0.1", "169.254.1.1", "fe80::1", "fc00::1", "100.64.1.1", "0.0.0.0", "224.0.0.1", "::ffff:192.168.1.1"} {
		if IsPublicIP(netip.MustParseAddr(ip)) {
			t.Errorf("not public: %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if !IsPublicIP(netip.MustParseAddr(ip)) {
			t.Errorf("public: %s", ip)
		}
	}
}

// Optional integration coverage with real local files; no test downloads data.
func TestGeoIPLocalDatabases(t *testing.T) {
	v4, v6 := os.Getenv("TEST_IP_V4_DB_PATH"), os.Getenv("TEST_IP_V6_DB_PATH")
	if v4 == "" || v6 == "" {
		t.Skip("set TEST_IP_V4_DB_PATH and TEST_IP_V6_DB_PATH for real xdb tests")
	}
	s, err := NewGeoIPService(v4, v6)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		for addr, code := range map[string]string{"1.2.3.4": "AU", "240e:3b7:3272:d8d0:db09:c067:8d59:539e": "CN"} {
			wg.Add(1)
			go func(addr, code string) {
				defer wg.Done()
				loc, err := s.Lookup(netip.MustParseAddr(addr))
				if err != nil || loc.CountryCode == nil || *loc.CountryCode != code {
					t.Errorf("lookup %s: %+v %v", addr, loc, err)
				}
			}(addr, code)
		}
	}
	wg.Wait()
	partial, err := NewGeoIPService(v4, filepath.Join(t.TempDir(), "missing-v6.xdb"))
	if err == nil {
		t.Fatal("missing IPv6 database should report an error")
	}
	loc, err := partial.Lookup(netip.MustParseAddr("1.2.3.4"))
	if err != nil || loc.CountryCode == nil || *loc.CountryCode != "AU" {
		t.Fatal("IPv6 failure disabled IPv4")
	}
}

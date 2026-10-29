package service

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// IPLocation contains approximate network location, not a physical address.
type IPLocation struct {
	CountryCode *string `json:"countryCode"`
	Country     *string `json:"country"`
	Region      *string `json:"region"`
	City        *string `json:"city"`
}

// GeoIPService reads local xdb files only. No lookup initiates network I/O.
type GeoIPService struct {
	mu sync.Mutex // xdb.Search mutates its IO counter even with a full buffer.
	v4 *xdb.Searcher
	v6 *xdb.Searcher
}

// NewGeoIPService returns a usable service even if a database is unavailable.
// A failed family does not disable the other family or prevent server startup.
func NewGeoIPService(v4Path, v6Path string) (*GeoIPService, error) {
	s := &GeoIPService{}
	var errs []error
	for _, db := range []struct {
		path    string
		version *xdb.Version
		target  **xdb.Searcher
	}{{v4Path, xdb.IPv4, &s.v4}, {v6Path, xdb.IPv6, &s.v6}} {
		if db.path == "" {
			continue
		}
		searcher, err := loadGeoIP(db.path, db.version)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s database: %w", db.version.Name, err))
			continue
		}
		*db.target = searcher
	}
	return s, errors.Join(errs...)
}

func loadGeoIP(path string, version *xdb.Version) (*xdb.Searcher, error) {
	if err := xdb.VerifyFromFile(path); err != nil {
		return nil, err
	}
	header, err := xdb.LoadHeaderFromFile(path)
	if err != nil {
		return nil, err
	}
	actual, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, err
	}
	if actual.Id != version.Id {
		return nil, fmt.Errorf("expected %s, got %s", version.Name, actual.Name)
	}
	buffer, err := xdb.LoadContentFromFile(path)
	if err != nil {
		return nil, err
	}
	return xdb.NewWithBuffer(version, buffer)
}

func (s *GeoIPService) Lookup(ip netip.Addr) (IPLocation, error) {
	if s == nil || !IsPublicIP(ip) {
		return IPLocation{}, nil
	}
	ip = ip.Unmap()
	searcher := s.v6
	if ip.Is4() {
		searcher = s.v4
	}
	if searcher == nil {
		return IPLocation{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := searcher.Search(ip.String())
	if err != nil {
		return IPLocation{}, err
	}
	return parseIPLocation(raw), nil
}

func IsPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// ip2region v3 data: Country|Province|City|ISP|ISO alpha-2.
// Legacy data without an ISO field is not guessed into a country code.
func parseIPLocation(raw string) IPLocation {
	fields := strings.Split(raw, "|")
	if len(fields) != 5 {
		return IPLocation{}
	}
	code := strings.ToUpper(strings.TrimSpace(fields[4]))
	if code != "0" && (len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z') {
		return IPLocation{}
	}
	return IPLocation{Country: geoValue(fields[0]), Region: geoValue(fields[1]), City: geoValue(fields[2]), CountryCode: geoValue(code)}
}

func geoValue(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return nil
	}
	return &value
}

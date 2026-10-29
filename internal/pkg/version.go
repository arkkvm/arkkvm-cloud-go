// Package pkg holds small domain-agnostic helpers shared across layers.
package pkg

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version is a parsed three-segment version number, mirroring the legacy
// VersionUtils (deployed branch): system versions are major.minor.yyMMddHH,
// app versions are major.minor.yyMMdd + build number, hence patch is int64.
type Version struct {
	Major int
	Minor int
	Patch int64
}

var versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// ParseVersion strictly parses "x.y.z" (digits only; the device side strips
// any "-dev" style suffix before reporting). Anything else is an error,
// matching the deployed-branch behavior of failing the request.
func ParseVersion(s string) (Version, error) {
	if s == "" || !versionRe.MatchString(s) {
		return Version{}, fmt.Errorf("invalid version format: %q", s)
	}
	parts := strings.Split(s, ".")
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return Version{}, fmt.Errorf("invalid version format: %q", s)
	}
	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// Compare returns 1 if a > b, 0 if equal, -1 if a < b.
func Compare(a, b Version) int {
	if a.Major != b.Major {
		if a.Major > b.Major {
			return 1
		}
		return -1
	}
	if a.Minor != b.Minor {
		if a.Minor > b.Minor {
			return 1
		}
		return -1
	}
	switch {
	case a.Patch > b.Patch:
		return 1
	case a.Patch < b.Patch:
		return -1
	default:
		return 0
	}
}

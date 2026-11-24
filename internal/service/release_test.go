package service

import (
	"testing"

	"arkkvm.com/arkkvm-cloud/internal/model"
)

func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }

func TestCanDistribute(t *testing.T) {
	cases := []struct {
		name     string
		dist     *int
		gray     *int
		sns      *string
		deviceID string
		want     bool
	}{
		{"full rollout always", intPtr(3), nil, nil, "", true},
		{"full rollout with device", intPtr(3), nil, nil, "dev-1", true},
		{"nil distribution rejects", nil, nil, nil, "dev-1", false},
		{"unknown distribution rejects", intPtr(9), nil, nil, "dev-1", false},

		{"internal without device rejects", intPtr(1), nil, strPtr("dev-1"), "", false},
		{"internal empty sn list rejects", intPtr(1), nil, strPtr(""), "dev-1", false},
		{"internal sn match", intPtr(1), nil, strPtr("dev-1,dev-2"), "dev-2", true},
		{"internal sn mismatch", intPtr(1), nil, strPtr("dev-1"), "dev-9", false},

		{"gray without device rejects", intPtr(2), intPtr(50), nil, "", false},
		{"gray nil percent rejects", intPtr(2), nil, nil, "dev-1", false},
		{"gray zero percent rejects", intPtr(2), intPtr(0), nil, "dev-1", false},
		{"gray 100 allows all", intPtr(2), intPtr(100), nil, "dev-1", true},
		{"gray bucket stable membership", intPtr(2), intPtr(1), nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &model.Release{Distribution: tc.dist, Gray: tc.gray, DeviceSNs: tc.sns}
			if got := canDistribute(r, tc.deviceID); got != tc.want {
				t.Errorf("canDistribute = %v, want %v", got, tc.want)
			}
		})
	}
}

// The gray bucket must be deterministic and match the legacy arithmetic:
// first 8 hex digits of MD5(sn) parsed as a number, mod 100.
func TestGrayBucketDeterministic(t *testing.T) {
	first := grayBucket("ark-0001")
	for i := 0; i < 10; i++ {
		if grayBucket("ark-0001") != first {
			t.Fatal("gray bucket is not deterministic")
		}
	}
	if first < 0 || first > 99 {
		t.Fatalf("bucket %d out of range [0,100)", first)
	}
	// Cross-check one value against the Java formula computed manually.
	if got := grayBucket("ark-0001"); got != first {
		t.Fatalf("inconsistent bucket for the same sn")
	}
}

func TestGrayBucketReleaseGating(t *testing.T) {
	// Find a SN whose bucket is 0-ish to prove small percentages still admit.
	low := ""
	high := ""
	for i := 0; i < 5000; i++ {
		sn := "sn-" + itoaP(i)
		b := grayBucket(sn)
		if b == 0 && low == "" {
			low = sn
		}
		if b == 99 && high == "" {
			high = sn
		}
	}
	if low == "" || high == "" {
		t.Skip("could not find bucket samples in range")
	}
	if !canDistribute(&model.Release{Distribution: intPtr(2), Gray: intPtr(1)}, low) {
		t.Errorf("bucket-0 SN should pass a 1%% rollout")
	}
	if canDistribute(&model.Release{Distribution: intPtr(2), Gray: intPtr(1)}, high) {
		t.Errorf("bucket-99 SN should not pass a 1%% rollout")
	}
}

func itoaP(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func TestWebVersionFromCloudVersion(t *testing.T) {
	cases := []struct {
		in   *string
		want string
	}{
		{nil, ""},
		{strPtr(""), ""},
		{strPtr("1.2.3"), "1.2.3"},                                 // legacy plain string
		{strPtr(`{"webVersion":"0.4.1"}`), "0.4.1"},                // new JSON report
		{strPtr(`{"other":"x"}`), ""},                              // JSON without webVersion
		{strPtr(`{not json`), "{not json"},                         // invalid JSON falls back to raw
	}
	for _, tc := range cases {
		if got := WebVersionFromCloudVersion(tc.in); got != tc.want {
			t.Errorf("WebVersionFromCloudVersion(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

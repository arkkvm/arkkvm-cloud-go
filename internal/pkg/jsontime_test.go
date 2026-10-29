package pkg

import (
	"encoding/json"
	"testing"
	"time"
)

// JsonTime must render exactly like Jackson rendered java.util.Date in the
// legacy API: milliseconds always present, numeric offset (never "Z").
func TestJsonTimeMarshalsLikeJackson(t *testing.T) {
	ts := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	out, err := json.Marshal(JsonTime(ts))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `"2026-09-01T12:00:00.000+00:00"` {
		t.Errorf("got %s, want Jackson-style ISO-8601 with millis and +00:00", out)
	}
}

func TestJsonTimeRoundTrip(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 600000000, time.UTC)
	data, err := json.Marshal(JsonTime(ts))
	if err != nil {
		t.Fatal(err)
	}
	var back JsonTime
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !time.Time(back).Equal(ts) {
		t.Errorf("round trip mismatch: %v != %v", time.Time(back), ts)
	}
}

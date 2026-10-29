package pkg

import (
	"strconv"
	"time"
)

// JsonTime serializes time.Time exactly like Jackson serialized java.util.Date
// in the legacy API: ISO-8601 with mandatory milliseconds and a numeric UTC
// offset, e.g. "2026-09-01T12:00:00.000+00:00" (never the "Z" shorthand that
// Go's default RFC3339 produces). All timestamps are stored and served in UTC.
type JsonTime time.Time

func (t JsonTime) MarshalJSON() ([]byte, error) {
	stamp := time.Time(t).UTC().Format("2006-01-02T15:04:05.000-07:00")
	return []byte(strconv.Quote(stamp)), nil
}

func (t *JsonTime) UnmarshalJSON(b []byte) error {
	s, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.999999999-07:00", s)
	if err != nil {
		return err
	}
	*t = JsonTime(parsed)
	return nil
}

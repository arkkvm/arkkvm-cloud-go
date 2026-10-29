package pkg

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    Version
		wantErr bool
	}{
		{"1.0.10091", Version{1, 0, 10091}, false},
		{"0.1.26052240005", Version{0, 1, 26052240005}, false}, // app build numbers exceed int32
		{"2.0.0", Version{2, 0, 0}, false},
		{"", Version{}, true},
		{"1.0", Version{}, true},
		{"1.0.0.1", Version{}, true},
		{"1.0.10091-dev", Version{}, true}, // device must strip suffixes
		{"a.b.c", Version{}, true},
	}
	for _, tc := range cases {
		got, err := ParseVersion(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseVersion(%q): expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVersion(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b Version
		want int
	}{
		{Version{1, 0, 1}, Version{1, 0, 2}, -1},
		{Version{1, 1, 0}, Version{1, 0, 9999}, 1},
		{Version{2, 0, 0}, Version{1, 9, 9999}, 1},
		{Version{0, 1, 26052240005}, Version{0, 1, 26052240005}, 0},
		{Version{0, 1, 9223372036854775807}, Version{0, 1, 1}, 1},
	}
	for _, tc := range cases {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

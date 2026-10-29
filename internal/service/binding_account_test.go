package service

import (
	"errors"
	"testing"
)

func TestBoundAccountHintMasking(t *testing.T) {
	if !errors.Is(&DeviceBindingConflict{}, ErrDeviceAlreadyBound) {
		t.Fatal("conflict must retain legacy errors.Is compatibility")
	}
	for _, raw := range []string{"", " ", "invalid", "@example.com", "owner@"} {
		if maskedAccountEmail(&raw) != nil {
			t.Fatalf("invalid email exposed: %q", raw)
		}
	}
	for _, tc := range []struct{ raw, want string }{
		{"owner@example.com", "o***@example.com"},
		{" a@example.com ", "a***@example.com"},
	} {
		got := maskedAccountEmail(&tc.raw)
		if got == nil || *got != tc.want {
			t.Fatalf("email masking failed: %v", got)
		}
	}
	for _, tc := range []struct{ raw, want string }{
		{"Owner Name", "O***"}, {"\u738b\u4e09", "\u738b***"}, {"\u738b", "***"},
	} {
		got := maskedAccountName(&tc.raw)
		if got == nil || *got != tc.want {
			t.Fatalf("name masking failed: %v", got)
		}
	}
	if maskedAccountName(nil) != nil || maskedAccountEmail(nil) != nil {
		t.Fatal("missing profile must stay missing")
	}
}

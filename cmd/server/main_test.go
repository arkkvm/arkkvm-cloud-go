package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"arkkvm.com/arkkvm-cloud/internal/service"
)

type fakeProvider struct{ name string }

func (f fakeProvider) Name() string                         { return f.name }
func (f fakeProvider) AuthURL(baseURL, state string) string { return baseURL }
func (f fakeProvider) Exchange(context.Context, string, string) (*service.Identity, error) {
	return nil, nil
}
func (f fakeProvider) RequiresState() bool { return true }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func providerNames(providers []service.OAuthProvider) []string {
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.Name()
	}
	return names
}

// TestWithoutDisabledProviders covers the withdrawal knob CN uses to drop
// google: matched names disappear, order is preserved, and the no-op paths
// (empty list, unknown name) leave the registry untouched.
func TestWithoutDisabledProviders(t *testing.T) {
	all := func() []service.OAuthProvider {
		return []service.OAuthProvider{
			fakeProvider{"google"},
			fakeProvider{"microsoft"},
			fakeProvider{"github"},
		}
	}

	tests := []struct {
		name     string
		disabled []string
		want     []string
	}{
		{"none disabled", nil, []string{"google", "microsoft", "github"}},
		{"google withdrawn keeps order", []string{"google"}, []string{"microsoft", "github"}},
		{"case and spaces ignored", []string{" Google "}, []string{"microsoft", "github"}},
		{"unknown name is a no-op", []string{"facebook"}, []string{"google", "microsoft", "github"}},
		{"multiple withdrawn", []string{"google", "github"}, []string{"microsoft"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := providerNames(withoutDisabledProviders(all(), tt.disabled, testLogger()))
			if len(got) != len(tt.want) {
				t.Fatalf("providers = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("providers = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

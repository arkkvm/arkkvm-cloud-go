package config

import (
	"os"
	"path/filepath"
	"testing"
)

// loadEnv sets the secrets Validate insists on; nothing here needs real values.
func loadEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ARK_DB_DSN", "root:pw@tcp(db:3306)/ark-kvm-test?charset=utf8mb4")
	t.Setenv("COOKIE_SIGNING_KEY", "cookie-key")
	t.Setenv("KEYSTORE_PATH", "/data/keystore/server.p12")
	t.Setenv("ARK_JWT_SECRET", "jwt-secret")
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestLoadMergesDisabledProviders pins the viper overlay semantics the CN
// withdrawal depends on: the region file replaces the base list.
func TestLoadMergesDisabledProviders(t *testing.T) {
	loadEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), "server:\n  port: 6612\n")
	writeFile(t, filepath.Join(dir, "config.cn.yaml"), "oauth2:\n  disabled-providers:\n    - google\n")

	t.Setenv("ARK_ENV_MODE", "cn")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(cn): %v", err)
	}
	if got := cfg.OAuth2.DisabledProviders; len(got) != 1 || got[0] != "google" {
		t.Fatalf("disabled-providers = %v, want [google]", got)
	}
}

// TestLocalModeIgnoresCNOverlay keeps the withdrawal region-scoped: without
// ARK_ENV_MODE=cn the overlay is never read, so testing/global keep google.
func TestLocalModeIgnoresCNOverlay(t *testing.T) {
	loadEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), "server:\n  port: 6612\n")
	writeFile(t, filepath.Join(dir, "config.cn.yaml"), "oauth2:\n  disabled-providers:\n    - google\n")

	t.Setenv("ARK_ENV_MODE", "local")
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(local): %v", err)
	}
	if got := cfg.OAuth2.DisabledProviders; len(got) != 0 {
		t.Fatalf("disabled-providers = %v, want empty", got)
	}
}

// TestRepoCNOverlayWithdrawsGoogle guards the shipped CN overlay itself: a
// deleted entry would silently bring the unreachable Google button back.
func TestRepoCNOverlayWithdrawsGoogle(t *testing.T) {
	loadEnv(t)
	t.Setenv("ARK_ENV_MODE", "cn")
	cfg, err := Load("../../configs")
	if err != nil {
		t.Fatalf("Load(repo configs): %v", err)
	}
	for _, name := range cfg.OAuth2.DisabledProviders {
		if name == "google" {
			return
		}
	}
	t.Fatalf("configs/config.cn.yaml must list google in oauth2.disabled-providers, got %v", cfg.OAuth2.DisabledProviders)
}

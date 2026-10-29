package config

import "testing"

func TestIPEnvironmentConfig(t *testing.T) {
	t.Setenv("ARK_ENV_MODE", "local")
	t.Setenv("ARK_DB_DSN", "test")
	t.Setenv("COOKIE_SIGNING_KEY", "test")
	t.Setenv("ARK_JWT_SECRET", "test")
	t.Setenv("ARK_IP_V4_DB_PATH", "/data/geoip/v4.xdb")
	t.Setenv("ARK_IP_V6_DB_PATH", "/data/geoip/v6.xdb")
	t.Setenv("ARK_IP_TRUSTED_PROXIES", "127.0.0.1/32,::1/128")
	cfg, err := Load("../../configs")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IP.V4DBPath != "/data/geoip/v4.xdb" || cfg.IP.V6DBPath != "/data/geoip/v6.xdb" || len(cfg.IP.TrustedProxies) != 2 || cfg.IP.TrustedProxies[1] != "::1/128" {
		t.Fatalf("incorrect IP environment config: %+v", cfg.IP)
	}
}

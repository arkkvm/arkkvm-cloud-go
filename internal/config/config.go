// Package config loads application configuration.
// Precedence: env vars > configs/config.<env>.yaml > configs/config.yaml > defaults.
// The environment is selected via ARK_ENV_MODE (testing/prod), matching the legacy ENV_MODE convention.
package config

import (
	"arkkvm.com/arkkvm-cloud/internal/pkg"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	IP struct {
		V4DBPath       string   `mapstructure:"v4-db-path"`
		V6DBPath       string   `mapstructure:"v6-db-path"`
		TrustedProxies []string `mapstructure:"trusted-proxies"`
	} `mapstructure:"ip"`

	Server struct {
		Port int `mapstructure:"port"`
	} `mapstructure:"server"`

	DB struct {
		Driver string `mapstructure:"driver"` // mysql | postgres (reserved for phase 2, doc 09)
		DSN    string `mapstructure:"dsn"`
	} `mapstructure:"db"`

	Redis struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`

	OAuth2 struct {
		Google struct {
			ClientID      string `mapstructure:"client-id"`
			ClientSecret  string `mapstructure:"client-secret"`
			RedirectURI   string `mapstructure:"redirect-uri"` // template {baseUrl}/oauth2/code/google
			Scope         string `mapstructure:"scope"`
			AuthURI       string `mapstructure:"auth-uri"`
			TokenURI      string `mapstructure:"token-uri"`
			JWKSURI       string `mapstructure:"jwks-uri"`
			VerifyIDToken bool   `mapstructure:"verify-id-token"` // legacy config retained; Google signature verification is always enforced
		} `mapstructure:"google"`
		// New providers: registered only when client-id/app-id is non-empty
		// (doc 14 §6). Google keeps its legacy block and is always served —
		// unless DisabledProviders withdraws it for this deployment.
		Microsoft struct {
			ClientID     string `mapstructure:"client-id"` // env OAUTH_MICROSOFT_CLIENT_ID
			ClientSecret string `mapstructure:"client-secret"`
			RedirectURI  string `mapstructure:"redirect-uri"` // template {baseUrl}/oauth2/code/microsoft
			Scope        string `mapstructure:"scope"`
			Tenant       string `mapstructure:"tenant"` // default common (iss prefix/suffix-checked)
			AuthURI      string `mapstructure:"auth-uri"`
			TokenURI     string `mapstructure:"token-uri"`
			JWKSURI      string `mapstructure:"jwks-uri"`
		} `mapstructure:"microsoft"`
		GitHub struct {
			ClientID     string `mapstructure:"client-id"` // env OAUTH_GITHUB_CLIENT_ID
			ClientSecret string `mapstructure:"client-secret"`
			RedirectURI  string `mapstructure:"redirect-uri"` // template {baseUrl}/oauth2/code/github
			Scope        string `mapstructure:"scope"`
			AuthURI      string `mapstructure:"auth-uri"`
			TokenURI     string `mapstructure:"token-uri"`
			UserAPI      string `mapstructure:"user-api"`
			EmailsAPI    string `mapstructure:"emails-api"`
		} `mapstructure:"github"`
		WeChat struct {
			AppID        string `mapstructure:"app-id"` // env OAUTH_WECHAT_APP_ID
			AppSecret    string `mapstructure:"app-secret"`
			RedirectURI  string `mapstructure:"redirect-uri"` // domain must match the registered 授权回调域
			QRConnectURI string `mapstructure:"qrconnect-uri"`
			TokenURI     string `mapstructure:"token-uri"`
			UserInfoURI  string `mapstructure:"userinfo-uri"`
		} `mapstructure:"wechat"`
		Apple struct {
			ClientID    string `mapstructure:"client-id"`   // Apple Services ID, env OAUTH_APPLE_CLIENT_ID
			TeamID      string `mapstructure:"team-id"`     // env OAUTH_APPLE_TEAM_ID (client JWT iss)
			KeyID       string `mapstructure:"key-id"`      // env OAUTH_APPLE_KEY_ID (client JWT kid)
			PrivateKey  string `mapstructure:"private-key"` // p8 PEM (\n-escaped or file path), env OAUTH_APPLE_PRIVATE_KEY
			RedirectURI string `mapstructure:"redirect-uri"`
			Scope       string `mapstructure:"scope"`
			AuthURI     string `mapstructure:"auth-uri"`
			TokenURI    string `mapstructure:"token-uri"`
			JWKSURI     string `mapstructure:"jwks-uri"`
		} `mapstructure:"apple"`
		// DisabledProviders withdraws providers this deployment does not
		// offer, even when their credentials are present (config.cn.yaml
		// drops google: its endpoints are unreachable from mainland China,
		// so the button only led into a dead authorize round-trip). A
		// disabled provider gets no routes and is absent from
		// /oidc/providers; stored identities are untouched, so re-enabling
		// is a config-only change.
		DisabledProviders []string `mapstructure:"disabled-providers"`
		AllowedReturnURLs []string `mapstructure:"allowed-return-urls"`
		// Phase-C gate skeleton (doc 14 §7C, 05 §3.1): when set, google
		// PAIRING redirects stop carrying the legacy clientId/oidcGoogle
		// params for devices whose cloud_version >= this threshold.
		// Empty = never stop (today's behavior). Devices with unknown or
		// unparseable version (first pairing, never connected) always keep
		// receiving the params — the conservative default, since omitting
		// them is the only breaking direction in the whole migration.
		Pairing struct {
			StopLegacyParamsVersion string `mapstructure:"stop-legacy-params-version"` // env OAUTH_PAIRING_STOP_LEGACY_PARAMS_VERSION
		} `mapstructure:"pairing"`
		Cookie struct {
			SigningKey string `mapstructure:"signing-key"`
			MaxAge     int    `mapstructure:"max-age"`
			Secure     bool   `mapstructure:"secure"`
		} `mapstructure:"cookie"`
		// Whether to trust X-Forwarded-* headers when deriving the OAuth base URL.
		TrustProxyHeaders bool `mapstructure:"trust-proxy-headers"`
		// Legacy setting retained for config compatibility; /oidc/quick is retired.
		QuickLoginRequireSecret bool `mapstructure:"quick-login-require-secret"`
	} `mapstructure:"oauth2"`

	WebRTC struct {
		Cloudflare struct {
			TurnKeyID    string `mapstructure:"turn-key-id"`
			TurnAPIToken string `mapstructure:"turn-api-token"`
		} `mapstructure:"cloudflare"`
		SelfHosted struct {
			Secret   string   `mapstructure:"secret"`    // coturn static-auth-secret, env TURN_STATIC_AUTH_SECRET
			TurnURLs []string `mapstructure:"turn-urls"` // e.g. turn:stun.arkkvm.cn:3478?transport=udp
		} `mapstructure:"selfhosted"`
		ICEServers []string `mapstructure:"ice-servers"`
	} `mapstructure:"webrtc"`

	Release struct {
		DownloadCDN string `mapstructure:"download-cdn"`
	} `mapstructure:"release"`

	Sign struct {
		Keystore struct {
			Path     string `mapstructure:"path"`
			Password string `mapstructure:"password"`
		} `mapstructure:"keystore"`
	} `mapstructure:"sign"`

	Security struct {
		// Strip oidcToken from /me and secretToken from /devices/{id} by default (doc 06 §5).
		// Enable temporarily only if the frontend is confirmed to consume those fields.
		ExposeSensitiveFields bool `mapstructure:"expose-sensitive-fields"`
	} `mapstructure:"security"`

	Auth struct {
		// HS256 secret for the Sa-Token-shaped session tokens. The server treats
		// tokens as opaque strings (validity lives in Redis), but device firmware
		// and web clients parse them, so the JWT shape must stay byte-compatible
		// with the legacy deployment. Same value as the old sa-token.jwt-secret-key.
		JWTSecret string `mapstructure:"jwt-secret-key"` // env ARK_JWT_SECRET
	} `mapstructure:"auth"`

	CORS struct {
		AllowOrigins []string `mapstructure:"allow-origins"` // default ["*"], matching current behavior
	} `mapstructure:"cors"`

	Log struct {
		Level string `mapstructure:"level"` // debug | info | warn | error
	} `mapstructure:"log"`

	WS struct {
		HeartbeatInterval time.Duration `mapstructure:"heartbeat-interval"` // server->device heartbeat period, default 60s
		ReadDeadline      time.Duration `mapstructure:"read-deadline"`      // default 180s (1.5x the legacy 120s idle timeout)
		WriteTimeout      time.Duration `mapstructure:"write-timeout"`      // timeout when the send channel is full, default 30s
		SendBufferSize    int           `mapstructure:"send-buffer-size"`   // per-connection send buffer, default 256
		MaxMessageSize    int64         `mapstructure:"max-message-size"`   // default 512KB, aligned with the legacy container
	} `mapstructure:"ws"`
}

func (c *Config) Validate() error {
	for _, raw := range c.OAuth2.AllowedReturnURLs {
		if _, err := pkg.ParseOAuthReturnURL(raw); err != nil {
			return fmt.Errorf("oauth2.allowed-return-urls contains an invalid callback")
		}
	}
	if c.DB.DSN == "" {
		return fmt.Errorf("db.dsn is not configured (ARK_DB_DSN)")
	}
	if c.OAuth2.Cookie.SigningKey == "" {
		return fmt.Errorf("oauth2.cookie.signing-key is not configured (COOKIE_SIGNING_KEY)")
	}
	if c.Sign.Keystore.Path == "" {
		return fmt.Errorf("sign.keystore.path is not configured")
	}
	if c.Auth.JWTSecret == "" {
		return fmt.Errorf("auth.jwt-secret-key is not configured (ARK_JWT_SECRET, must equal the legacy sa-token jwt-secret-key)")
	}
	if c.DB.Driver == "" {
		c.DB.Driver = "mysql"
	}
	return nil
}

func Load(configDir string) (*Config, error) {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("ARK_ENV_MODE")))
	if env == "" {
		env = "local"
	}

	v := viper.New()
	v.SetConfigName("config")
	v.AddConfigPath(configDir)

	// Bool defaults must go through SetDefault: Unmarshal cannot distinguish
	// "not set" from a false zero value.
	v.SetDefault("oauth2.google.verify-id-token", true)
	v.SetDefault("oauth2.cookie.secure", true)
	v.SetDefault("oauth2.quick-login-require-secret", true)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config.yaml: %w", err)
	}
	if env != "local" {
		v.SetConfigName("config." + env)
		if err := v.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("read config.%s.yaml: %w", env, err)
		}
	}

	// Secrets are provided exclusively via environment variables (doc 08 §2.3).
	bindEnv(v, map[string]string{
		"ip.v4-db-path":                             "ARK_IP_V4_DB_PATH",
		"ip.v6-db-path":                             "ARK_IP_V6_DB_PATH",
		"ip.trusted-proxies":                        "ARK_IP_TRUSTED_PROXIES",
		"server.port":                               "ARK_SERVER_PORT",
		"db.driver":                                 "ARK_DB_DRIVER",
		"db.dsn":                                    "ARK_DB_DSN",
		"redis.addr":                                "ARK_REDIS_ADDR",
		"redis.password":                            "ARK_REDIS_PASSWORD",
		"redis.db":                                  "ARK_REDIS_DB",
		"oauth2.allowed-return-urls":                "OAUTH_ALLOWED_RETURN_URLS",
		"oauth2.google.client-id":                   "OAUTH_GOOGLE_CLIENT_ID",
		"oauth2.google.client-secret":               "OAUTH_GOOGLE_CLIENT_SECRET",
		"oauth2.microsoft.client-id":                "OAUTH_MICROSOFT_CLIENT_ID",
		"oauth2.microsoft.client-secret":            "OAUTH_MICROSOFT_CLIENT_SECRET",
		"oauth2.github.client-id":                   "OAUTH_GITHUB_CLIENT_ID",
		"oauth2.github.client-secret":               "OAUTH_GITHUB_CLIENT_SECRET",
		"oauth2.wechat.app-id":                      "OAUTH_WECHAT_APP_ID",
		"oauth2.wechat.app-secret":                  "OAUTH_WECHAT_APP_SECRET",
		"oauth2.apple.client-id":                    "OAUTH_APPLE_CLIENT_ID",
		"oauth2.apple.team-id":                      "OAUTH_APPLE_TEAM_ID",
		"oauth2.apple.key-id":                       "OAUTH_APPLE_KEY_ID",
		"oauth2.apple.private-key":                  "OAUTH_APPLE_PRIVATE_KEY",
		"oauth2.pairing.stop-legacy-params-version": "OAUTH_PAIRING_STOP_LEGACY_PARAMS_VERSION",
		"oauth2.cookie.signing-key":                 "COOKIE_SIGNING_KEY",
		"webrtc.cloudflare.turn-key-id":             "TURN_KEY_ID",
		"webrtc.cloudflare.turn-api-token":          "TURN_API_TOKEN",
		"webrtc.selfhosted.secret":                  "TURN_STATIC_AUTH_SECRET",
		"sign.keystore.path":                        "KEYSTORE_PATH",
		"sign.keystore.password":                    "KEYSTORE_PASSWORD",
		"auth.jwt-secret-key":                       "ARK_JWT_SECRET",
		"release.download-cdn":                      "RELEASE_DOWNLOAD_CDN",
		"log.level":                                 "ARK_LOG_LEVEL",
	})

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	applyDefaults(&cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyDefaults(c *Config) {
	if c.Server.Port == 0 {
		c.Server.Port = 6612
	}
	if c.OAuth2.Google.Scope == "" {
		c.OAuth2.Google.Scope = "openid email profile"
	}
	if c.OAuth2.Google.RedirectURI == "" {
		c.OAuth2.Google.RedirectURI = "{baseUrl}/oauth2/code/google"
	}
	if c.OAuth2.Microsoft.RedirectURI == "" {
		c.OAuth2.Microsoft.RedirectURI = "{baseUrl}/oauth2/code/microsoft"
	}
	if c.OAuth2.GitHub.RedirectURI == "" {
		c.OAuth2.GitHub.RedirectURI = "{baseUrl}/oauth2/code/github"
	}
	if c.OAuth2.WeChat.RedirectURI == "" {
		c.OAuth2.WeChat.RedirectURI = "{baseUrl}/oauth2/code/wechat"
	}
	if c.OAuth2.Apple.RedirectURI == "" {
		c.OAuth2.Apple.RedirectURI = "{baseUrl}/oauth2/code/apple"
	}
	if c.OAuth2.Cookie.MaxAge == 0 {
		c.OAuth2.Cookie.MaxAge = 86400
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if len(c.CORS.AllowOrigins) == 0 {
		c.CORS.AllowOrigins = []string{"*"}
	}
	if c.WS.HeartbeatInterval == 0 {
		c.WS.HeartbeatInterval = 60 * time.Second
	}
	if c.WS.ReadDeadline == 0 {
		c.WS.ReadDeadline = 180 * time.Second
	}
	if c.WS.WriteTimeout == 0 {
		c.WS.WriteTimeout = 30 * time.Second
	}
	if c.WS.SendBufferSize == 0 {
		c.WS.SendBufferSize = 256
	}
	if c.WS.MaxMessageSize == 0 {
		c.WS.MaxMessageSize = 512 * 1024
	}
}

func bindEnv(v *viper.Viper, m map[string]string) {
	for key, env := range m {
		_ = v.BindEnv(key, env)
	}
}

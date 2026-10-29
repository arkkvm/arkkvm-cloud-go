// Command server is the arkkvm-cloud API: REST endpoints plus the two
// WebSocket signaling channels. Wiring is explicit and linear — config,
// infrastructure, repositories, services, hub, endpoints, router, HTTP
// server with graceful shutdown.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/arkkvm/arkkvm-cloud-go/internal/api"
	"github.com/arkkvm/arkkvm-cloud-go/internal/api/handler"
	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
	"github.com/arkkvm/arkkvm-cloud-go/internal/config"
	"github.com/arkkvm/arkkvm-cloud-go/internal/repository"
	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
	"github.com/arkkvm/arkkvm-cloud-go/internal/ws"
)

var version = "dev" // set via -ldflags "-X main.version=..."

func main() {
	configDir := flag.String("config-dir", "./configs", "configuration directory")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		os.Stdout.WriteString(version + "\n")
		return
	}

	cfg, err := config.Load(*configDir)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	level := parseLevel(cfg.Log.Level)
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).
		With("app", "arkkvm-cloud", "version", version)
	slog.SetDefault(log)

	db, err := openDB(cfg)
	if err != nil {
		log.Error("failed to connect database", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Infrastructure & services.
	tokens := auth.NewTokenService(rdb, cfg.Auth.JWTSecret)
	cookies := auth.NewCookieManager(cfg.OAuth2.Cookie.SigningKey, cfg.OAuth2.Cookie.MaxAge, cfg.OAuth2.Cookie.Secure)

	userRepo := repository.NewUserRepo(db)
	identityRepo := repository.NewIdentityRepo(db)
	deviceRepo := repository.NewDeviceRepo(db)
	releaseRepo := repository.NewReleaseRepo(db)
	turnRepo := repository.NewTurnActivityRepo(db)
	// Dedicated arkkvm_mcp credential: long-lived, DB-backed,
	// revocable — never a Login session (single-session coexistence).
	mcpTokenRepo := repository.NewMcpTokenRepo(db)
	mcpTokens := auth.NewMcpTokenService(mcpTokenRepo)

	signer, err := service.NewSigner(cfg.Sign.Keystore.Path, cfg.Sign.Keystore.Password)
	if err != nil {
		log.Error("failed to load signing keystore", "error", err)
		os.Exit(1)
	}

	users := service.NewUserService(userRepo, identityRepo)

	// OAuth registry: google is served with its legacy wire
	// behavior unless the deployment withdraws it; the new providers register
	// only when fully configured (empty
	// client-id/app-id OR secret -> no routes — a half-configured provider
	// would lead users into an authorize round-trip whose token exchange
	// always fails). One HTTP client and one JWKS cache (keyed by URI) are
	// shared across providers.
	oauthClient := &http.Client{Timeout: 10 * time.Second}
	sharedJWKS := service.NewJWKSCache(oauthClient)
	oauthProviders := []service.OAuthProvider{
		service.NewGoogleProvider(service.GoogleProviderConfig{
			ClientID:      cfg.OAuth2.Google.ClientID,
			ClientSecret:  cfg.OAuth2.Google.ClientSecret,
			RedirectURI:   cfg.OAuth2.Google.RedirectURI,
			Scope:         cfg.OAuth2.Google.Scope,
			AuthURI:       cfg.OAuth2.Google.AuthURI,
			TokenURI:      cfg.OAuth2.Google.TokenURI,
			JWKSURI:       cfg.OAuth2.Google.JWKSURI,
			VerifyIDToken: cfg.OAuth2.Google.VerifyIDToken,
		}, oauthClient, sharedJWKS),
	}
	if cfg.OAuth2.Microsoft.ClientID != "" && cfg.OAuth2.Microsoft.ClientSecret != "" {
		oauthProviders = append(oauthProviders, service.NewMicrosoftProvider(service.MicrosoftProviderConfig{
			ClientID:     cfg.OAuth2.Microsoft.ClientID,
			ClientSecret: cfg.OAuth2.Microsoft.ClientSecret,
			RedirectURI:  cfg.OAuth2.Microsoft.RedirectURI,
			Scope:        cfg.OAuth2.Microsoft.Scope,
			Tenant:       cfg.OAuth2.Microsoft.Tenant,
			AuthURI:      cfg.OAuth2.Microsoft.AuthURI,
			TokenURI:     cfg.OAuth2.Microsoft.TokenURI,
			JWKSURI:      cfg.OAuth2.Microsoft.JWKSURI,
		}, oauthClient, sharedJWKS))
	}
	if cfg.OAuth2.GitHub.ClientID != "" && cfg.OAuth2.GitHub.ClientSecret != "" {
		oauthProviders = append(oauthProviders, service.NewGitHubProvider(service.GitHubProviderConfig{
			ClientID:     cfg.OAuth2.GitHub.ClientID,
			ClientSecret: cfg.OAuth2.GitHub.ClientSecret,
			RedirectURI:  cfg.OAuth2.GitHub.RedirectURI,
			Scope:        cfg.OAuth2.GitHub.Scope,
			AuthURI:      cfg.OAuth2.GitHub.AuthURI,
			TokenURI:     cfg.OAuth2.GitHub.TokenURI,
			UserAPI:      cfg.OAuth2.GitHub.UserAPI,
			EmailsAPI:    cfg.OAuth2.GitHub.EmailsAPI,
		}, oauthClient))
	}
	if cfg.OAuth2.WeChat.AppID != "" && cfg.OAuth2.WeChat.AppSecret != "" {
		oauthProviders = append(oauthProviders, service.NewWeChatProvider(service.WeChatProviderConfig{
			AppID:        cfg.OAuth2.WeChat.AppID,
			AppSecret:    cfg.OAuth2.WeChat.AppSecret,
			RedirectURI:  cfg.OAuth2.WeChat.RedirectURI,
			QRConnectURI: cfg.OAuth2.WeChat.QRConnectURI,
			TokenURI:     cfg.OAuth2.WeChat.TokenURI,
			UserInfoURI:  cfg.OAuth2.WeChat.UserInfoURI,
		}, oauthClient))
	}
	// Apple needs all four: without any one of them the client JWT cannot be
	// minted, so a partial config must not register (same half-config rule).
	if cfg.OAuth2.Apple.ClientID != "" && cfg.OAuth2.Apple.TeamID != "" &&
		cfg.OAuth2.Apple.KeyID != "" && cfg.OAuth2.Apple.PrivateKey != "" {
		oauthProviders = append(oauthProviders, service.NewAppleProvider(service.AppleProviderConfig{
			ClientID:    cfg.OAuth2.Apple.ClientID,
			TeamID:      cfg.OAuth2.Apple.TeamID,
			KeyID:       cfg.OAuth2.Apple.KeyID,
			PrivateKey:  cfg.OAuth2.Apple.PrivateKey,
			RedirectURI: cfg.OAuth2.Apple.RedirectURI,
			Scope:       cfg.OAuth2.Apple.Scope,
			AuthURI:     cfg.OAuth2.Apple.AuthURI,
			TokenURI:    cfg.OAuth2.Apple.TokenURI,
			JWKSURI:     cfg.OAuth2.Apple.JWKSURI,
		}, oauthClient, sharedJWKS))
	}
	// A deployment may withdraw providers it cannot serve (CN drops google).
	oauthProviders = withoutDisabledProviders(oauthProviders, cfg.OAuth2.DisabledProviders, log)
	turnSvc := service.NewTurnService(service.TurnConfig{
		CloudflareKeyID:    cfg.WebRTC.Cloudflare.TurnKeyID,
		CloudflareAPIToken: cfg.WebRTC.Cloudflare.TurnAPIToken,
		StaticStun:         cfg.WebRTC.ICEServers,
		SelfHostedSecret:   cfg.WebRTC.SelfHosted.Secret,
		SelfHostedTurnURLs: cfg.WebRTC.SelfHosted.TurnURLs,
	})
	releases := service.NewReleaseService(releaseRepo, signer, cfg.Release.DownloadCDN)

	// Hub wiring: device disconnect updates last_seen (legacy behavior).
	hub := ws.NewHub(log, func(deviceID string) {
		_ = deviceRepo.UpdateLastSeen(deviceID)
	})
	devices := service.NewDeviceService(deviceRepo, hub)

	// WebSocket endpoints.
	wsOpts := ws.Options{
		SendBuffer:        cfg.WS.SendBufferSize,
		WriteTimeout:      cfg.WS.WriteTimeout,
		ReadDeadline:      cfg.WS.ReadDeadline,
		HeartbeatInterval: cfg.WS.HeartbeatInterval,
		MaxMessageSize:    cfg.WS.MaxMessageSize,
	}
	lifetime, shutdown := context.WithCancel(context.Background())
	deviceWS := &ws.DeviceEndpoint{
		Hub: hub, RealDevice: devices, Options: wsOpts, Log: log, Lifetime: lifetime,
	}
	iceCredIssuer := func() []ws.ICEServerCred {
		ice, err := turnSvc.CachedCredentials(lifetime)
		if err != nil || ice == nil || len(ice.URLs) == 0 {
			return nil
		}
		return []ws.ICEServerCred{{URLs: ice.URLs, Username: ice.Username, Credential: ice.Credential}}
	}
	clientWS := &ws.ClientEndpoint{
		Hub: hub, Tokens: tokens, McpTokens: mcpTokens, Devices: devices, Users: users,
		ICEServers: cfg.WebRTC.ICEServers, ICECredIssuer: iceCredIssuer,
		Options: wsOpts, Log: log, Lifetime: lifetime,
	}

	// HTTP surface. Release mode silences Gin's debug route table; application
	// logging is handled exclusively by slog.
	gin.SetMode(gin.ReleaseMode)
	handler.SetExposeSensitive(cfg.Security.ExposeSensitiveFields)
	geoIP, geoErr := service.NewGeoIPService(cfg.IP.V4DBPath, cfg.IP.V6DBPath)
	if geoErr != nil {
		log.Warn("IP location database unavailable; affected lookups return no location", "error", geoErr)
	}
	ipHandler, err := handler.NewIPHandler(geoIP, cfg.IP.TrustedProxies)
	if err != nil {
		log.Error("invalid IP proxy configuration", "error", err)
		os.Exit(1)
	}
	router := api.NewRouter(api.Deps{
		IP:        ipHandler,
		Tokens:    tokens,
		Mcp:       handler.NewMcpHandler(tokens, mcpTokens),
		McpTokens: mcpTokens,
		Users:     handler.NewUserHandler(users, tokens),
		Devices:   handler.NewDeviceHandler(devices, tokens),
		OAuth: handler.NewOAuthHandler(oauthProviders, users, devices, tokens, cookies,
			cfg.OAuth2.TrustProxyHeaders, cfg.OAuth2.QuickLoginRequireSecret,
			cfg.OAuth2.Google.ClientID, cfg.OAuth2.Pairing.StopLegacyParamsVersion),
		Release: handler.NewReleaseHandler(releases),
		Webrtc:  handler.NewWebrtcHandler(hub, devices, turnSvc, turnRepo),
		ReadyCheck: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var one int
			if err := db.WithContext(ctx).Raw("SELECT 1").Scan(&one).Error; err != nil {
				return err
			}
			return rdb.Ping(ctx).Err()
		},
		DeviceWS: deviceWS,
		ClientWS: clientWS,
	})

	srv := &http.Server{
		Addr:              addrOf(cfg.Server.Port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Serve until SIGINT/SIGTERM, then drain gracefully.
	go func() {
		log.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx) // stops accepting; in-flight requests drain
	shutdown()                    // cancels WS lifetimes -> writer goroutines send Close frames
	_ = rdb.Close()
	closable, _ := db.DB()
	if closable != nil {
		_ = closable.Close()
	}
	log.Info("server stopped")
}

// withoutDisabledProviders drops the providers this deployment withdrew
// (oauth2.disabled-providers). Registration order is preserved so
// /oidc/providers keeps rendering the login page in a stable order. Unknown
// names are reported: a typo would otherwise leave the provider enabled with
// no sign that the withdrawal did not take effect.
func withoutDisabledProviders(providers []service.OAuthProvider, disabled []string, log *slog.Logger) []service.OAuthProvider {
	if len(disabled) == 0 {
		return providers
	}
	off := make(map[string]bool, len(disabled))
	for _, name := range disabled {
		off[strings.ToLower(strings.TrimSpace(name))] = true
	}
	kept := providers[:0]
	for _, p := range providers {
		if !off[p.Name()] {
			kept = append(kept, p)
			continue
		}
		delete(off, p.Name())
		log.Info("oauth provider withdrawn by config", "provider", p.Name())
	}
	for name := range off {
		log.Warn("oauth2.disabled-providers names an unregistered provider", "provider", name)
	}
	return kept
}

func openDB(cfg *config.Config) (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger:         gormlogger.Default.LogMode(gormlogger.Warn),
		TranslateError: true, // surfaces duplicate-key as gorm.ErrDuplicatedKey (identity upsert race)
	}
	switch cfg.DB.Driver {
	case "postgres":
		return gorm.Open(postgres.Open(cfg.DB.DSN), gormCfg)
	default:
		return gorm.Open(mysql.Open(cfg.DB.DSN), gormCfg)
	}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func addrOf(port int) string {
	if port == 0 {
		port = 6612
	}
	return fmt.Sprintf(":%d", port)
}

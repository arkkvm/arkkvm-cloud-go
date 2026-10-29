# Ark KVM Cloud

Cloud services supporting remote access and device connectivity for [ArkKVM](https://www.arkkvm.com/) — user login (OAuth2), device pairing and binding, WebRTC signaling, and release distribution for ArkKVM devices.

> This repository is the Go implementation of the Ark KVM Cloud API. It is an
> independent codebase — not a fork of the retired Java service at
> [arkkvm/arkkvm-cloud](https://github.com/arkkvm/arkkvm-cloud).

## Requirements

- Go: 1.26 or later
- MySQL: 8.x recommended (PostgreSQL is also supported — set `db.driver: postgres`)
- Redis: 6.x or 7.x recommended

## Build

Build:

```bash
make build
```

Run tests only:

```bash
make test
```

Lint and vet:

```bash
make lint
make vet
```

## Third-Party Setup

### OAuth2 Providers

Google is built in. Microsoft, GitHub, WeChat, and Apple register
automatically once both the client id and secret are configured — a
half-configured provider never exposes routes.

Create the OAuth client in Google Cloud Console:

- Console entry: https://console.cloud.google.com/apis/credentials
- Guide: https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid
- Choose `Web application` as the client type.
- Add your backend callback URL to `Authorized redirect URIs`, for example:
  - `https://your-domain.com/oauth2/code/google`
  - `http://localhost:6612/oauth2/code/google`

### WebRTC / TURN

This project uses Cloudflare Realtime TURN credentials.

- Dashboard/docs entry: https://developers.cloudflare.com/realtime/turn/generate-credentials/
- You need to create a TURN key in the Cloudflare Dashboard or via API.
- Store the generated `turn-key-id` and `turn-key-api-token` via `TURN_KEY_ID` and `TURN_API_TOKEN`.

Self-hosted TURN (coturn) is also supported: set `TURN_STATIC_AUTH_SECRET`
and `webrtc.selfhosted.turn-urls`.

## Generate the Keystore

The service loads a `PKCS12` keystore and uses its private key to sign
release packages.

Example command:

```bash
keytool -genkeypair \
  -alias arkkvm \
  -keyalg RSA \
  -keysize 2048 \
  -sigalg SHA256withRSA \
  -storetype PKCS12 \
  -keystore server.p12 \
  -validity 3650 \
  -storepass arkkvm \
  -keypass arkkvm \
  -dname "CN=ArkKVM, OU=Dev, O=ArkKVM, L=Shanghai, ST=Shanghai, C=CN"
```

Then point the service to it:

```bash
export KEYSTORE_PATH=/absolute/path/to/server.p12
export KEYSTORE_PASSWORD=arkkvm
```

Notes:

- The keystore type must be `PKCS12`.
- `KEYSTORE_PASSWORD` must match the keystore password set above.

## Configuration

Configuration lives in `configs/`. `config.yaml` is the base profile; an
environment overlay (`config.testing.yaml`, `config.prod.yaml`,
`config.cn.yaml`) is merged on top when `ARK_ENV_MODE` is set (default:
`local`, base only).

All secrets are provided via environment variables — never committed to
config files.

| Variable | Purpose |
|----------|---------|
| `ARK_ENV_MODE` | Config overlay: `local` (default) / `testing` / `prod` / `cn` |
| `ARK_SERVER_PORT` | HTTP port (default `6612`) |
| `ARK_DB_DRIVER` | `mysql` (default) or `postgres` |
| `ARK_DB_DSN` | Database DSN, e.g. `user:pass@tcp(mysql:3306)/ark-kvm?charset=utf8mb4&parseTime=True&loc=UTC` |
| `ARK_REDIS_ADDR` / `ARK_REDIS_PASSWORD` / `ARK_REDIS_DB` | Redis connection |
| `ARK_JWT_SECRET` | JWT signing secret |
| `COOKIE_SIGNING_KEY` | OAuth cookie signing key |
| `OAUTH_GOOGLE_CLIENT_ID` / `OAUTH_GOOGLE_CLIENT_SECRET` | Google OAuth2 |
| `OAUTH_MICROSOFT_CLIENT_ID` / `OAUTH_MICROSOFT_CLIENT_SECRET` | Microsoft OAuth2 (optional) |
| `OAUTH_GITHUB_CLIENT_ID` / `OAUTH_GITHUB_CLIENT_SECRET` | GitHub OAuth2 (optional) |
| `OAUTH_WECHAT_APP_ID` / `OAUTH_WECHAT_APP_SECRET` | WeChat Open Platform (optional) |
| `OAUTH_APPLE_CLIENT_ID` / `OAUTH_APPLE_TEAM_ID` / `OAUTH_APPLE_KEY_ID` / `OAUTH_APPLE_PRIVATE_KEY` | Sign in with Apple (optional; all four required) |
| `TURN_KEY_ID` / `TURN_API_TOKEN` | Cloudflare TURN credentials |
| `TURN_STATIC_AUTH_SECRET` | Self-hosted coturn static-auth-secret (optional) |
| `KEYSTORE_PATH` / `KEYSTORE_PASSWORD` | PKCS12 keystore for release signing |
| `RELEASE_DOWNLOAD_CDN` | CDN base URL for release downloads |
| `ARK_IP_V4_DB_PATH` / `ARK_IP_V6_DB_PATH` | Optional ip2region databases for visitor IP location |

## Local Run

The default application port is `6612`.

1. Prepare MySQL.

- Create a database such as `ark-kvm`.
- Export `ARK_DB_DSN`, for example:
  `user:pass@tcp(localhost:3306)/ark-kvm?charset=utf8mb4&parseTime=True&loc=UTC`

2. Prepare Redis.

- Start a standalone Redis instance.
- Export `ARK_REDIS_ADDR` (default `localhost:6379`) and `ARK_REDIS_PASSWORD` if set.

3. Generate a keystore.

- Create a `server.p12` file with the command shown above.
- Export `KEYSTORE_PATH` and `KEYSTORE_PASSWORD`.

4. Prepare Google OAuth2.

- Create a Google OAuth client.
- Export `OAUTH_GOOGLE_CLIENT_ID` and `OAUTH_GOOGLE_CLIENT_SECRET`.
- Set the redirect URI to your backend callback, for example `http://localhost:6612/oauth2/code/google`.

5. Prepare Cloudflare TURN credentials.

- Create a TURN key in Cloudflare.
- Export `TURN_KEY_ID` and `TURN_API_TOKEN`.

6. Start the application.

```bash
make run
```

7. Verify the service.

- Health check: `http://localhost:6612/healthz`
- Readiness (DB + Redis): `http://localhost:6612/readyz`
- Login providers: `http://localhost:6612/oidc/providers`
- OAuth callback: `http://localhost:6612/oauth2/code/google`
- Device WebSocket: `ws://localhost:6612/`
- Client WebSocket signaling: `ws://localhost:6612/webrtc/signaling/client`

## Docker

A multi-stage `Dockerfile` compiles the service inside the container — the
host needs no Go toolchain:

```bash
make docker
```

When building from a region-constrained network, pass the module proxy
explicitly (the image build downloads Go modules itself):

```bash
docker build -f deployments/Dockerfile \
  --build-arg GOPROXY=https://goproxy.cn,direct \
  -t arkkvm-cloud:dev .
```

For a full testing stack (service + MySQL + Redis), see
[deployments/docker-compose.yaml](deployments/docker-compose.yaml). Secrets
come from the `.env` file or the shell — never commit them.

## Notes

- Google OAuth2 client credentials are configured via `OAUTH_GOOGLE_CLIENT_ID` / `OAUTH_GOOGLE_CLIENT_SECRET`.
- Cloudflare TURN settings are configured via `TURN_KEY_ID` / `TURN_API_TOKEN`.
- Keystore settings are configured via `KEYSTORE_PATH` / `KEYSTORE_PASSWORD`.
- A deployment may withdraw any provider via `oauth2.disabled-providers` (for example, drop Google in mainland China).
- `security.expose-sensitive-fields` (default `false`) strips `oidcToken`/`secretToken` from API responses.

## License

ArkKVM Cloud is licensed under **GPL-2.0-or-later**. Official releases of
this repository are distributed under **GNU GPL version 3** to remain
compatible with Apache-2.0 dependencies (see [NOTICE](NOTICE)).

| Document | Description |
|----------|-------------|
| [LICENSE](LICENSE) | GNU GPL v2 full text |
| [NOTICE](NOTICE) | Copyright and GPLv3 distribution election |

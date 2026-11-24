package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"arkkvm.com/arkkvm-cloud/internal/auth"
	"arkkvm.com/arkkvm-cloud/internal/model"
	"arkkvm.com/arkkvm-cloud/internal/service"
)

// --- fakes implementing the handler's narrow service interfaces ---

type fakeOAuthUsers struct {
	userID int64
	ident  *service.Identity
	got    string
	err    error
}

func (f *fakeOAuthUsers) UpsertByIdentity(_ context.Context, provider string, ident *service.Identity) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.got = provider
	f.ident = ident
	return f.userID, nil
}

type fakeOAuthDevices struct {
	bound        map[string]int64 // deviceID -> userID it was bound to
	secret       string
	ownID        int64
	cloudVersion *string // surfaced by GetByID for the phase-C gate
}

func (f *fakeOAuthDevices) BindDevice(_ context.Context, deviceID string, userID int64) (bool, error) {
	if f.bound == nil {
		f.bound = map[string]int64{}
	}
	if owner, ok := f.bound[deviceID]; ok && owner != userID {
		return false, nil
	}
	f.bound[deviceID] = userID
	return true, nil
}

func (f *fakeOAuthDevices) FindBySecretToken(_ context.Context, secret string) (string, *string, error) {
	if secret != "" && secret == f.secret {
		return "dev-1", nil, nil
	}
	return "", nil, nil
}

func (f *fakeOAuthDevices) GetByID(_ context.Context, deviceID string) (*model.Device, error) {
	return &model.Device{ID: deviceID, UserID: f.ownID, CloudVersion: f.cloudVersion}, nil
}

func strPtr(v string) *string { return &v }

// fakeProvider is a configurable non-google provider.
type fakeProvider struct {
	name        string
	authState   string // the state AuthURL received
	exchangeErr error
	rawIDToken  string
}

func (f *fakeProvider) Name() string        { return f.name }
func (f *fakeProvider) RequiresState() bool { return true }

func (f *fakeProvider) AuthURL(baseURL, state string) string {
	f.authState = state
	return "https://idp.test/auth?state=" + state
}

func (f *fakeProvider) Exchange(_ context.Context, code, baseURL string) (*service.Identity, error) {
	if f.exchangeErr != nil {
		return nil, f.exchangeErr
	}
	return &service.Identity{ProviderUserID: "puid-" + f.name, Email: "x@y.z", EmailVerified: true, RawIDToken: f.rawIDToken}, nil
}

// --- harness ---

type oauthHarness struct {
	handler *OAuthHandler
	srv     *httptest.Server
	users   *fakeOAuthUsers
	devices *fakeOAuthDevices
	tokens  *auth.TokenService
}

func newOAuthHarness(t *testing.T, providers []service.OAuthProvider) *oauthHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	tokens := auth.NewTokenService(rdb, "test-secret")
	cookies := auth.NewCookieManager("cookie-key", 86400, false)

	users := &fakeOAuthUsers{userID: 42}
	devices := &fakeOAuthDevices{ownID: 42}
	h := &OAuthHandler{
		providers:         map[string]service.OAuthProvider{},
		users:             users,
		devices:           devices,
		tokens:            tokens,
		cookies:           cookies,
		clientID:          "google-client-id",
		allowedReturnURLs: []string{"https://app.example.com/ad-login"},
	}
	for _, p := range providers {
		h.providers[p.Name()] = p
		h.order = append(h.order, p.Name())
	}
	r := gin.New()
	for _, name := range h.order {
		name := name
		r.POST("/oidc/"+name, func(c *gin.Context) { h.Authorize(c, name) })
		r.GET("/oauth2/code/"+name, func(c *gin.Context) { h.Callback(c, name) })
		r.POST("/oauth2/code/"+name, func(c *gin.Context) { h.Callback(c, name) })
	}
	r.GET("/oidc/providers", h.Providers)
	r.GET("/oidc/quick", h.QuickLogin)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return &oauthHarness{handler: h, srv: srv, users: users, devices: devices, tokens: tokens}
}

// authorize runs POST /oidc/{name} without following the redirect; the
// returned response carries the signed cookies in its Set-Cookie headers.
func (h *oauthHarness) authorize(t *testing.T, name, form string) *http.Response {
	t.Helper()
	client := h.srv.Client()
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { client.CheckRedirect = checkRedirect }()

	resp, err := client.PostForm(h.srv.URL+"/oidc/"+name, mustValues(t, form))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return resp
}

// callback runs GET /oauth2/code/{name} carrying the cookies authorize set.
func (h *oauthHarness) callback(t *testing.T, authResp *http.Response, name, extraQuery string) *http.Response {
	t.Helper()
	client := h.srv.Client()
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { client.CheckRedirect = checkRedirect }()

	cb, err := http.NewRequest(http.MethodGet, h.srv.URL+"/oauth2/code/"+name+"?code=the-code"+extraQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range authResp.Cookies() {
		cb.AddCookie(c)
	}
	doResp, err := client.Do(cb)
	if err != nil {
		t.Fatal(err)
	}
	return doResp
}

// callbackPost mirrors callback() the way Apple delivers it:
// response_mode=form_post — code/state/user travel in the POST body, only
// the signed cookies ride the request headers.
func (h *oauthHarness) callbackPost(t *testing.T, authResp *http.Response, name string, form url.Values) *http.Response {
	t.Helper()
	client := h.srv.Client()
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { client.CheckRedirect = checkRedirect }()

	cb, err := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth2/code/"+name, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	cb.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range authResp.Cookies() {
		cb.AddCookie(c)
	}
	doResp, err := client.Do(cb)
	if err != nil {
		t.Fatal(err)
	}
	return doResp
}

// authorizeAndCallback chains the two steps when the extra callback query is
// known up front (no state round-trip needed).
func (h *oauthHarness) authorizeAndCallback(t *testing.T, name, form, extraQuery string) *http.Response {
	t.Helper()
	resp := h.authorize(t, name, form)
	defer resp.Body.Close()
	if name == "google" && !strings.Contains(extraQuery, "state=") {
		u, _ := url.Parse(resp.Header.Get("Location"))
		extraQuery += "&state=" + url.QueryEscape(u.Query().Get("state"))
	}
	return h.callback(t, resp, name, extraQuery)
}

func mustValues(t *testing.T, form string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(form)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func queryOf(t *testing.T, location string) url.Values {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// Provider cryptographic validation is covered by service tests; these tests
// verify handler redirects, cookies, session and legacy pairing contracts.
func newGoogleTestProvider(t *testing.T) (service.OAuthProvider, string) {
	t.Helper()
	idToken := makeTestIDToken(t, map[string]any{"sub": "g-sub-9"})
	return &fakeProvider{name: "google", rawIDToken: idToken}, idToken
}

// makeTestIDToken builds an unsigned (parse-only) id_token.
func makeTestIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := "eyJhbGciOiJSUzI1NiIsa2lkIjoiazEifQ" // {"alg":"RS256","kid":"k1"}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// GOLDEN: the google pairing callback must keep the full legacy query —
// token + clientId + oidcGoogle + deviceId — plus the additive loginToken
// (cloud webapp session for the /ad-login?sn=1 handoff), and no state
// parameter. Legacy consumers (old firmware pairing chain, old webapp)
// ignore the unknown param, so additive is safe.
func TestGoogleCallbackPairingQueryGolden(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})

	resp := h.authorizeAndCallback(t, "google",
		"returnTo=https://app.example.com/ad-login&deviceId=dev-1", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://app.example.com/ad-login") {
		t.Fatalf("redirect target: %s", loc)
	}
	assertCredentialFreeCallback(t, h, resp)
}

// An already claimed device must not prevent account selection at login.
func TestGoogleCallbackDoesNotClaimDeviceOwnedByAnotherAccount(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	h.devices.bound = map[string]int64{"dev-1": 99}
	resp := h.authorizeAndCallback(t, "google",
		"returnTo=https://app.example.com/ad-login&deviceId=dev-1", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("account selection must succeed, got %d", resp.StatusCode)
	}
	if h.devices.bound["dev-1"] != 99 {
		t.Fatal("OAuth must not modify existing ownership")
	}
}

// Plain web login keeps its session token but no longer forwards Google credentials.
func TestGoogleCallbackWebLoginQueryGolden(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})

	resp := h.authorizeAndCallback(t, "google", "returnTo=https://app.example.com/ad-login", "")
	defer resp.Body.Close()
	assertCredentialFreeCallback(t, h, resp)
}

// New providers: state enforced, callback query trimmed to
// token+deviceId+loginToken.
func TestNewProviderCallbackQueryAndState(t *testing.T) {
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})

	// Correct state flows through Authorize -> AuthURL -> callback; the
	// state only becomes known after the authorize call.
	authResp := h.authorize(t, "github", "returnTo=https://app.example.com/ad-login&deviceId=dev-2")
	defer authResp.Body.Close()
	if fp.authState == "" {
		t.Fatal("state must be generated and passed to AuthURL")
	}
	resp := h.callback(t, authResp, "github", "&state="+fp.authState)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	assertCredentialFreeCallback(t, h, resp)
}

func TestNewProviderRejectsWrongState(t *testing.T) {
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})
	resp := h.authorizeAndCallback(t, "github", "returnTo=https://app.example.com/ad-login", "&state=tampered")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("state mismatch must 400, got %d", resp.StatusCode)
	}
}

func TestNewProviderRejectsMissingState(t *testing.T) {
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})
	resp := h.authorizeAndCallback(t, "github", "returnTo=https://app.example.com/ad-login", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing state must 400, got %d", resp.StatusCode)
	}
}

// Apple delivers its callback via response_mode=form_post: code and state
// travel in the POST body, the signed cookies in the headers. The flow must
// behave exactly like the query-string redirect of the other providers.
func TestFormPostCallbackReadsBodyParams(t *testing.T) {
	fp := &fakeProvider{name: "apple"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})

	authResp := h.authorize(t, "apple", "returnTo=https://app.example.com/ad-login&deviceId=dev-9")
	defer authResp.Body.Close()
	if fp.authState == "" {
		t.Fatal("state must be generated for form_post providers too")
	}
	resp := h.callbackPost(t, authResp, "apple", url.Values{
		"code":  {"the-code"},
		"state": {fp.authState},
		"user":  {`{"name":{"firstName":"Jane","lastName":"Doe"}}`},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	assertCredentialFreeCallback(t, h, resp)
}

// The state check must not be bypassable by moving it out of the body.
func TestFormPostCallbackRejectsWrongState(t *testing.T) {
	fp := &fakeProvider{name: "apple"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})
	authResp := h.authorize(t, "apple", "returnTo=https://app.example.com/ad-login")
	defer authResp.Body.Close()
	resp := h.callbackPost(t, authResp, "apple", url.Values{
		"code":  {"the-code"},
		"state": {"tampered"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("state mismatch via form body must 400, got %d", resp.StatusCode)
	}
}

func TestAuthorizeMissingReturnTo(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	resp, err := h.srv.Client().PostForm(h.srv.URL+"/oidc/google", url.Values{"deviceId": {"d"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "missing returnTo") {
		t.Fatalf("want 400 'missing returnTo', got %d %q", resp.StatusCode, body)
	}
}

func TestUnknownProvider404(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	client := h.srv.Client()
	resp, err := client.PostForm(h.srv.URL+"/oidc/nope", url.Values{"returnTo": {"https://x/"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown provider must 404, got %d", resp.StatusCode)
	}
}

func TestProvidersEndpoint(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{gp, fp})

	resp, err := h.srv.Client().Get(h.srv.URL + "/oidc/providers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var br BaseResult[struct {
		Providers []string `json:"providers"`
	}]
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		t.Fatal(err)
	}
	if !br.Success || br.Code != 1 {
		t.Fatalf("BaseResult shape: %+v", br)
	}
	want := []string{"google", "github"}
	if len(br.Data.Providers) != len(want) {
		t.Fatalf("providers = %v, want %v", br.Data.Providers, want)
	}
	for i := range want {
		if br.Data.Providers[i] != want[i] {
			t.Fatalf("providers = %v, want %v (registration order)", br.Data.Providers, want)
		}
	}
}

// --- phase-C gate skeleton (doc 14 §7C) ---

// Gate armed + device version (JSON webVersion form) >= threshold: the
// google pairing redirect drops clientId/oidcGoogle, keeping exactly
// token+deviceId+loginToken.
func TestGoogleCallbackGateStopsAtThreshold(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	h.handler.stopLegacyParamsVersion = "0.4.100"
	h.devices.cloudVersion = strPtr(`{"webVersion":"0.4.200"}`)

	resp := h.authorizeAndCallback(t, "google",
		"returnTo=https://app.example.com/ad-login&deviceId=dev-1", "")
	defer resp.Body.Close()
	assertCredentialFreeCallback(t, h, resp)
}

// Gate armed + plain-string device version below threshold: params kept.
func TestGoogleCallbackGateBelowThresholdKeepsParams(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	h.handler.stopLegacyParamsVersion = "0.4.100"
	h.devices.cloudVersion = strPtr("0.4.50")

	resp := h.authorizeAndCallback(t, "google",
		"returnTo=https://app.example.com/ad-login&deviceId=dev-1", "")
	defer resp.Body.Close()
	assertCredentialFreeCallback(t, h, resp)
}

// Unknown version (first pairing — BindDevice just created the row, or the
// device never reported): conservative default keeps the params.
func TestGoogleCallbackGateUnknownVersionKeepsParams(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	h.handler.stopLegacyParamsVersion = "0.4.100"
	h.devices.cloudVersion = nil // fresh pairing row has no version

	resp := h.authorizeAndCallback(t, "google",
		"returnTo=https://app.example.com/ad-login&deviceId=dev-1", "")
	defer resp.Body.Close()
	assertCredentialFreeCallback(t, h, resp)
}

// Plain web login never needs Google verification fields, regardless of
// the device-version migration gate.
func TestGoogleCallbackWebLoginOmitsGoogleFieldsRegardlessOfGate(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	h.handler.stopLegacyParamsVersion = "0.0.1"

	resp := h.authorizeAndCallback(t, "google", "returnTo=https://app.example.com/ad-login", "")
	defer resp.Body.Close()
	assertCredentialFreeCallback(t, h, resp)
}

// Malformed threshold fails safe (params kept) instead of breaking logins.
func TestGoogleCallbackGateMalformedThresholdFailsSafe(t *testing.T) {
	gp, _ := newGoogleTestProvider(t)
	h := newOAuthHarness(t, []service.OAuthProvider{gp})
	h.handler.stopLegacyParamsVersion = "not-a-version"
	h.devices.cloudVersion = strPtr("9.9.9")

	resp := h.authorizeAndCallback(t, "google",
		"returnTo=https://app.example.com/ad-login&deviceId=dev-1", "")
	defer resp.Body.Close()
	assertCredentialFreeCallback(t, h, resp)
}

// --- MCP grant flow (doc 16 §1/§3.3) ---

// Authorize cookies carry client=mcp; the callback must hand back a one-time
// grant code bound to req — NOT a session token (no Login: the browser
// session must survive) and no pairing/loginToken baggage.
func TestMcpCallbackIssuesGrantCodeNotSession(t *testing.T) {
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})

	authResp := h.authorize(t, "github",
		"returnTo=http://127.0.0.1:52190/ad-login&code_challenge=ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA&code_challenge_method=S256&client=mcp&req=req-abc")
	defer authResp.Body.Close()
	resp := h.callback(t, authResp, "github", "&state="+fp.authState)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://127.0.0.1:52190/ad-login?") {
		t.Fatalf("redirect target: %s", loc)
	}
	q := queryOf(t, loc)
	if len(q) != 2 || q.Get("code") == "" || q.Get("req") != "req-abc" {
		t.Fatalf("mcp redirect must carry exactly code+req, got %v", q)
	}
	// The code is single-use and exchanges to the originating flow only.
	uid, err := h.tokens.ExchangeMcpGrant(context.Background(), q.Get("code"), "req-abc", strings.Repeat("a", 43))
	if err != nil || uid != 42 {
		t.Fatalf("grant code must exchange with proof for user 42, got (%d, %v)", uid, err)
	}
	if _, err := h.tokens.ExchangeMcpGrant(context.Background(), q.Get("code"), "req-abc", strings.Repeat("a", 43)); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("grant code must be single-use, second consume err = %v", err)
	}
	// No session, no pairing token, no bind: the MCP branch is code-only.
	if h.devices.bound != nil {
		t.Fatalf("mcp flow must not bind devices: %v", h.devices.bound)
	}
}

// Minting the MCP grant code must leave the session store untouched: the
// user's browser session survives (single-session eviction is the exact bug
// this flow replaces).
func TestMcpGrantDoesNotEvictBrowserSession(t *testing.T) {
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})

	browser, err := h.tokens.Login(context.Background(), 42, "")
	if err != nil {
		t.Fatal(err)
	}

	authResp := h.authorize(t, "github",
		"returnTo=http://127.0.0.1:52190/ad-login&code_challenge=ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA&code_challenge_method=S256&client=mcp&req=req-1")
	defer authResp.Body.Close()
	resp := h.callback(t, authResp, "github", "&state="+fp.authState)
	defer resp.Body.Close()
	if q := queryOf(t, resp.Header.Get("Location")); q.Get("code") == "" {
		t.Fatalf("mcp redirect missing code: %v", q)
	}
	if _, _, err := h.tokens.Resolve(context.Background(), browser); err != nil {
		t.Fatalf("browser session must survive the MCP grant flow: %v", err)
	}
}

// An MCP authorize without req fails fast — a code bound to an empty req
// could never be exchanged (POST /mcp/token requires the binding).
func TestMcpAuthorizeRequiresReq(t *testing.T) {
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})
	resp, err := h.srv.Client().PostForm(h.srv.URL+"/oidc/github",
		url.Values{"returnTo": {"http://127.0.0.1:1/ad-login"}, "client": {"mcp"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

// A stale mcpClient cookie (user aborted an MCP login mid-flow) must not
// hijack the next plain browser login: the non-MCP authorize re-emits the
// markers as cleared, and the callback keeps the legacy query. The cookie
// handling below emulates a real browser jar: later Set-Cookies win, and
// MaxAge<0 entries are dropped from the jar.
func TestStaleMcpCookieDoesNotHijackBrowserLogin(t *testing.T) {
	fp := &fakeProvider{name: "github"}
	h := newOAuthHarness(t, []service.OAuthProvider{fp})

	stale := h.authorize(t, "github",
		"returnTo=http://127.0.0.1:52190/ad-login&code_challenge=ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA&code_challenge_method=S256&client=mcp&req=req-stale")
	defer stale.Body.Close()
	// The MCP flow is aborted here — its markers stay in the browser jar.

	fresh := h.authorize(t, "github", "returnTo=https://app.example.com/ad-login")
	defer fresh.Body.Close()

	jar := map[string]*http.Cookie{}
	for _, c := range stale.Cookies() {
		jar[c.Name] = c
	}
	var cookies []*http.Cookie
	for _, c := range fresh.Cookies() {
		jar[c.Name] = c
	}
	for _, c := range jar {
		if c.MaxAge >= 0 {
			cookies = append(cookies, c) // MaxAge<0 = deletion marker, dropped
		}
	}

	cb, err := http.NewRequest(http.MethodGet,
		h.srv.URL+"/oauth2/code/github?code=the-code&state="+fp.authState, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cookies {
		cb.AddCookie(c)
	}
	client := h.srv.Client()
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { client.CheckRedirect = checkRedirect }()
	resp, err := client.Do(cb)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertCredentialFreeCallback(t, h, resp)
}

func TestOAuthCallbackSetsSharedBrowserCookie(t *testing.T) {
	for _, deviceID := range []string{"", "dev-1"} {
		t.Run("device="+deviceID, func(t *testing.T) {
			provider := &fakeProvider{name: "github"}
			harness := newOAuthHarness(t, []service.OAuthProvider{provider})
			form := "returnTo=https://app.example.com/ad-login"
			if deviceID != "" {
				form += "&deviceId=" + deviceID
			}
			authorized := harness.authorize(t, "github", form)
			response := harness.callback(t, authorized, "github", "&state="+provider.authState)
			if response.StatusCode != 302 {
				t.Fatalf("callback status %d", response.StatusCode)
			}
			location, err := url.Parse(response.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if len(location.Query()) != 0 {
				t.Fatal("callback leaked credentials")
			}
			var session *http.Cookie
			for _, cookie := range response.Cookies() {
				if cookie.Name == auth.BrowserSessionCookieName {
					session = cookie
				}
			}
			if session == nil || session.Value == "" || session.Path != "/" || session.Domain != "" || !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteStrictMode {
				t.Fatal("OAuth did not establish the shared HttpOnly session")
			}
			if userID, _, err := harness.tokens.Resolve(context.Background(), session.Value); err != nil || userID != 42 {
				t.Fatal("Cookie is not the live browser session")
			}
			if deviceID != "" && session.Value == location.Query().Get("token") {
				t.Fatal("pairing credential used as browser session")
			}
		})
	}
}

func TestMcpOAuthDoesNotReplaceBrowserCookie(t *testing.T) {
	provider := &fakeProvider{name: "github"}
	harness := newOAuthHarness(t, []service.OAuthProvider{provider})
	authorized := harness.authorize(t, "github", "returnTo=http://127.0.0.1:52190/ad-login&code_challenge=ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA&code_challenge_method=S256&client=mcp&req=browser-independent")
	response := harness.callback(t, authorized, "github", "&state="+provider.authState)
	if response.StatusCode != 302 {
		t.Fatal("MCP grant failed")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == auth.BrowserSessionCookieName {
			t.Fatal("MCP grant replaced browser session")
		}
	}
}

func assertCredentialFreeCallback(t *testing.T, h *oauthHarness, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://app.example.com/ad-login" {
		t.Fatalf("unexpected redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == auth.BrowserSessionCookieName {
			uid, _, err := h.tokens.Resolve(context.Background(), cookie.Value)
			if err != nil || uid != 42 || !cookie.Secure || !cookie.HttpOnly {
				t.Fatal("invalid browser session")
			}
			return
		}
	}
	t.Fatal("missing browser session")
}

func TestMcpAuthorizeRejectsMissingOrPlainChallenge(t *testing.T) {
	h := newOAuthHarness(t, []service.OAuthProvider{&fakeProvider{name: "github"}})
	for _, extra := range []string{"", "&code_challenge=ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA&code_challenge_method=plain"} {
		r := h.authorize(t, "github", "returnTo=http://127.0.0.1:52190/ad-login&client=mcp&req=req-1"+extra)
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Fatalf("weak authorize accepted: %d", r.StatusCode)
		}
	}
}

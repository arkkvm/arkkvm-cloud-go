package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- GitHub ---

func ghFixture(t *testing.T, userJSON, emailsJSON string) (*githubProvider, *httptest.Server) {
	t.Helper()
	var tokenForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_ = r.ParseForm()
			tokenForm = r.PostForm
			if r.Header.Get("Accept") != "application/json" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			fmt.Fprint(w, `{"access_token":"gh-token"}`)
		case "/user":
			if r.Header.Get("Authorization") != "Bearer gh-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, userJSON)
		case "/user/emails":
			fmt.Fprint(w, emailsJSON)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := GitHubProviderConfig{
		ClientID:    "gh-client",
		RedirectURI: "{baseUrl}/oauth2/code/github",
		AuthURI:     srv.URL + "/login/oauth/authorize",
		TokenURI:    srv.URL + "/login/oauth/access_token",
		UserAPI:     srv.URL + "/user",
		EmailsAPI:   srv.URL + "/user/emails",
	}
	p := NewGitHubProvider(cfg, srv.Client())
	t.Cleanup(func() {
		if tokenForm != nil {
			for k, want := range map[string]string{
				"client_id":    "gh-client",
				"code":         "the-code",
				"redirect_uri": "https://app.example.com/oauth2/code/github",
			} {
				if got := tokenForm.Get(k); got != want {
					t.Errorf("token form[%s] = %q, want %q", k, got, want)
				}
			}
		}
	})
	return p, srv
}

func TestGitHubExchangeVerifiedPrimaryEmail(t *testing.T) {
	p, _ := ghFixture(t,
		`{"id":123456,"login":"octocat","name":"Octo Cat","avatar_url":"https://av/1.png"}`,
		`[{"email":"private@x.com","primary":true,"verified":true},
		  {"email":"public@x.com","primary":false,"verified":true}]`)
	ident, err := p.Exchange(context.Background(), "the-code", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ident.ProviderUserID != "123456" || ident.Email != "private@x.com" ||
		!ident.EmailVerified || ident.DisplayName != "Octo Cat" || ident.AvatarURL != "https://av/1.png" {
		t.Fatalf("identity mapping: %+v", ident)
	}
	if !p.RequiresState() {
		t.Fatal("github must require state")
	}
}

// Only primary && verified emails may surface as a verified identity.
func TestGitHubUnverifiedEmailIsIgnored(t *testing.T) {
	p, _ := ghFixture(t,
		`{"id":1,"login":"octocat"}`,
		`[{"email":"unverified@x.com","primary":true,"verified":false}]`)
	ident, err := p.Exchange(context.Background(), "the-code", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ident.Email != "" || ident.EmailVerified {
		t.Fatalf("unverified email must not surface: %+v", ident)
	}
	if ident.DisplayName != "octocat" {
		t.Fatalf("name fallback to login: %+v", ident)
	}
}

func TestGitHubAuthURLCarriesState(t *testing.T) {
	p, _ := ghFixture(t, `{}`, `[]`)
	got := p.AuthURL("https://app.example.com", "s1")
	for _, want := range []string{"client_id=gh-client", "state=s1", "scope=read%3Auser+user%3Aemail"} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize URL %q missing %q", got, want)
		}
	}
}

// --- WeChat ---

func wxFixture(t *testing.T, tokenJSON, userinfoJSON string) *wechatProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sns/oauth2/access_token"):
			if r.URL.Query().Get("appid") != "wx-app" || r.URL.Query().Get("secret") != "wx-secret" ||
				r.URL.Query().Get("code") != "the-code" || r.URL.Query().Get("grant_type") != "authorization_code" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, tokenJSON)
		case strings.HasSuffix(r.URL.Path, "/sns/userinfo"):
			fmt.Fprint(w, userinfoJSON)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := WeChatProviderConfig{
		AppID:        "wx-app",
		AppSecret:    "wx-secret",
		RedirectURI:  "{baseUrl}/oauth2/code/wechat",
		QRConnectURI: "https://open.weixin.qq.com/connect/qrconnect",
		TokenURI:     srv.URL + "/sns/oauth2/access_token",
		UserInfoURI:  srv.URL + "/sns/userinfo",
	}
	return NewWeChatProvider(cfg, srv.Client())
}

func TestWeChatUnionIDPreferred(t *testing.T) {
	p := wxFixture(t,
		`{"access_token":"at","openid":"o-open","unionid":"u-union"}`,
		`{"openid":"o-open","unionid":"u-union","nickname":"Nickname","headimgurl":"https://img/1.jpg"}`)
	ident, err := p.Exchange(context.Background(), "the-code", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ident.ProviderUserID != "u-union" || ident.DisplayName != "Nickname" ||
		ident.AvatarURL != "https://img/1.jpg" || ident.Email != "" || ident.EmailVerified {
		t.Fatalf("identity mapping: %+v", ident)
	}
	if !p.RequiresState() {
		t.Fatal("wechat must require state")
	}
}

func TestWeChatFallsBackToOpenID(t *testing.T) {
	p := wxFixture(t,
		`{"access_token":"at","openid":"o-open"}`,
		`{"openid":"o-open","nickname":"N"}`)
	ident, err := p.Exchange(context.Background(), "the-code", "https://app.example.com")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if ident.ProviderUserID != "o-open" {
		t.Fatalf("openid fallback: %+v", ident)
	}
}

func TestWeChatErrcodeIsAnError(t *testing.T) {
	p := wxFixture(t, `{"errcode":40029,"errmsg":"invalid code"}`, `{}`)
	if _, err := p.Exchange(context.Background(), "the-code", "https://app.example.com"); err == nil {
		t.Fatal("errcode 40029 must fail the exchange")
	}
}

func TestWeChatAuthURL(t *testing.T) {
	p := wxFixture(t, `{}`, `{}`)
	got := p.AuthURL("https://app.example.com", "s9")
	for _, want := range []string{
		"appid=wx-app",
		"scope=snsapi_login",
		"state=s9",
		"redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth2%2Fcode%2Fwechat",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("authorize URL %q missing %q", got, want)
		}
	}
}

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// wechatProvider implements the WeChat Open-Platform website (QR-scan) flow:
// qrconnect authorize page, then the code swaps for access_token+openid via
// a GET with the secret in the query (WeChat's design), then /sns/userinfo.
// provider_user_id = unionid when present, else openid. WeChat returns
// errors as HTTP 200 with a non-zero errcode — surfaced as failures here.
// The app-id/secret stay unconfigured until the open-platform qualification
// is ready (D2: code complete, verified against mocks only).
type wechatProvider struct {
	cfg    WeChatProviderConfig
	client *http.Client
}

// WeChatProviderConfig mirrors the oauth2.wechat config block.
type WeChatProviderConfig struct {
	AppID       string
	AppSecret   string
	RedirectURI string // template containing {baseUrl}; domain must match the
	// registered 授权回调域 (one domain per application)
	QRConnectURI string
	TokenURI     string
	UserInfoURI  string
}

func NewWeChatProvider(cfg WeChatProviderConfig, client *http.Client) *wechatProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.QRConnectURI == "" {
		cfg.QRConnectURI = "https://open.weixin.qq.com/connect/qrconnect"
	}
	if cfg.TokenURI == "" {
		cfg.TokenURI = "https://api.weixin.qq.com/sns/oauth2/access_token"
	}
	if cfg.UserInfoURI == "" {
		cfg.UserInfoURI = "https://api.weixin.qq.com/sns/userinfo"
	}
	return &wechatProvider{cfg: cfg, client: client}
}

func (p *wechatProvider) Name() string        { return "wechat" }
func (p *wechatProvider) RequiresState() bool { return true }

type wechatTokenResponse struct {
	AccessToken string `json:"access_token"`
	OpenID      string `json:"openid"`
	UnionID     string `json:"unionid"`
	ErrCode     *int64 `json:"errcode"` // pointer: absent on success
	ErrMsg      string `json:"errmsg"`
}

type wechatUserInfo struct {
	OpenID     string   `json:"openid"`
	UnionID    string   `json:"unionid"`
	Nickname   string   `json:"nickname"`
	HeadImgURL string   `json:"headimgurl"`
	ErrCode    *int64   `json:"errcode"`
	ErrMsg     string   `json:"errmsg"`
	Privilege  []string `json:"privilege"`
}

// AuthURL builds the qrconnect (scan-to-login) URL. state is mandatory.
func (p *wechatProvider) AuthURL(baseURL, state string) string {
	q := url.Values{}
	q.Set("appid", p.cfg.AppID)
	q.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	q.Set("response_type", "code")
	q.Set("scope", "snsapi_login")
	q.Set("state", state)
	return p.cfg.QRConnectURI + "?" + q.Encode()
}

// Exchange swaps the code for the WeChat identity. WeChat users carry no
// email — Email stays empty, so the D1-conservative upsert never links them
// to an existing account (independent account creation by design).
func (p *wechatProvider) Exchange(ctx context.Context, code, baseURL string) (*Identity, error) {
	// WeChat's token endpoint takes no redirect_uri (unlike Google/GitHub);
	// the code alone is bound to the app.
	tokQ := url.Values{}
	tokQ.Set("appid", p.cfg.AppID)
	tokQ.Set("secret", p.cfg.AppSecret) // WeChat requires the secret as a query parameter
	tokQ.Set("code", code)
	tokQ.Set("grant_type", "authorization_code")

	var tok wechatTokenResponse
	if err := p.getJSON(ctx, p.cfg.TokenURI+"?"+tokQ.Encode(), &tok); err != nil {
		return nil, err
	}
	if tok.ErrCode != nil && *tok.ErrCode != 0 {
		return nil, fmt.Errorf("wechat token endpoint: errcode %d (%s)", *tok.ErrCode, tok.ErrMsg)
	}
	if tok.AccessToken == "" || tok.OpenID == "" {
		return nil, fmt.Errorf("wechat token endpoint returned no access_token/openid")
	}

	infoQ := url.Values{}
	infoQ.Set("access_token", tok.AccessToken)
	infoQ.Set("openid", tok.OpenID)
	infoQ.Set("lang", "zh_CN")
	var info wechatUserInfo
	if err := p.getJSON(ctx, p.cfg.UserInfoURI+"?"+infoQ.Encode(), &info); err != nil {
		return nil, err
	}
	if info.ErrCode != nil && *info.ErrCode != 0 {
		return nil, fmt.Errorf("wechat userinfo endpoint: errcode %d (%s)", *info.ErrCode, info.ErrMsg)
	}

	uid := info.UnionID
	if uid == "" {
		uid = tok.UnionID // unionid may ride on the token response only
	}
	if uid == "" {
		uid = info.OpenID
	}
	if uid == "" {
		uid = tok.OpenID
	}
	return &Identity{
		ProviderUserID: uid,
		DisplayName:    info.Nickname,
		AvatarURL:      info.HeadImgURL,
	}, nil
}

func (p *wechatProvider) getJSON(ctx context.Context, uri string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wechat endpoint returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

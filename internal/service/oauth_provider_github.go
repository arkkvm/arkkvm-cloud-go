package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// githubProvider implements the GitHub OAuth2 flow (OAuth2 + REST, no
// id_token): the code swaps for an access_token, then /user and /user/emails
// supply the identity. An email counts as verified only when GitHub marks it
// primary && verified.
type githubProvider struct {
	cfg    GitHubProviderConfig
	client *http.Client
}

// GitHubProviderConfig mirrors the oauth2.github config block.
type GitHubProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string // template containing {baseUrl}
	Scope        string
	AuthURI      string
	TokenURI     string
	UserAPI      string
	EmailsAPI    string
}

func NewGitHubProvider(cfg GitHubProviderConfig, client *http.Client) *githubProvider {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Scope == "" {
		cfg.Scope = "read:user user:email"
	}
	if cfg.AuthURI == "" {
		cfg.AuthURI = "https://github.com/login/oauth/authorize"
	}
	if cfg.TokenURI == "" {
		cfg.TokenURI = "https://github.com/login/oauth/access_token"
	}
	if cfg.UserAPI == "" {
		cfg.UserAPI = "https://api.github.com/user"
	}
	if cfg.EmailsAPI == "" {
		cfg.EmailsAPI = "https://api.github.com/user/emails"
	}
	return &githubProvider{cfg: cfg, client: client}
}

func (p *githubProvider) Name() string        { return "github" }
func (p *githubProvider) RequiresState() bool { return true }

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// AuthURL builds the GitHub authorize URL. state is mandatory.
func (p *githubProvider) AuthURL(baseURL, state string) string {
	q := url.Values{}
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))
	q.Set("scope", p.cfg.Scope)
	q.Set("state", state)
	return p.cfg.AuthURI + "?" + q.Encode()
}

// Exchange swaps the code for the GitHub identity.
func (p *githubProvider) Exchange(ctx context.Context, code, baseURL string) (*Identity, error) {
	form := url.Values{}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", strings.ReplaceAll(p.cfg.RedirectURI, "{baseUrl}", baseURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json") // token endpoint would answer form-encoded otherwise

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}
	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint returned no access_token")
	}

	var user githubUser
	if err := p.getJSON(ctx, tokens.AccessToken, p.cfg.UserAPI, &user); err != nil {
		return nil, err
	}
	if user.ID == 0 {
		return nil, fmt.Errorf("/user returned no id")
	}

	// Emails: unverified addresses must not surface as a verified identity.
	var emails []githubEmail
	email, verified := "", false
	if err := p.getJSON(ctx, tokens.AccessToken, p.cfg.EmailsAPI, &emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified && e.Email != "" {
				email, verified = e.Email, true
				break
			}
		}
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}
	return &Identity{
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Email:          email,
		EmailVerified:  verified,
		DisplayName:    name,
		AvatarURL:      user.AvatarURL,
	}, nil
}

func (p *githubProvider) getJSON(ctx context.Context, accessToken, uri string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", uri, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

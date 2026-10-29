package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"gorm.io/gorm"

	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
	"github.com/arkkvm/arkkvm-cloud-go/internal/repository"
)

// userStore / identityStore abstract the repositories so the upsert policy
// is unit-testable without a database.
type userStore interface {
	FindByID(id int64) (*model.User, error)
	Create(u *model.User) error
	Update(id int64, cols map[string]any) error
}

type identityStore interface {
	FindByProviderUID(provider, providerUserID string) (*model.UserIdentity, error)
	Create(id *model.UserIdentity) error
	UpdateProfile(id int64, cols map[string]any) error
	ListByUser(userID int64) ([]model.UserIdentity, error)
}

type UserService struct {
	users      userStore
	identities identityStore
}

func NewUserService(users *repository.UserRepo, identities *repository.IdentityRepo) *UserService {
	return &UserService{users: users, identities: identities}
}

// UpsertByIdentity resolves a login identity to a user id (,
// D1 conservative: NO email-based linking — providers only ever match on
// (provider, provider_user_id) or create a fresh user; different providers
// are always distinct accounts):
// 1. identity hit -> refresh non-empty identity and user profile fields;
// google additionally syncs oidc_token for the legacy offer frame;
// 2. no hit -> create the user + identity (google fills the legacy
// columns; others write email for display only; wechat has none).
//
// Google identity hits are guaranteed for pre-existing users by the
// user_identities backfill (deployments/mysql/001_user_identities.sql).
func (s *UserService) UpsertByIdentity(ctx context.Context, provider string, ident *Identity) (int64, error) {
	// Providers may omit profile fields on repeat authorization. Normalize a
	// copy so whitespace cannot erase previously stored profile information.
	profile := *ident
	profile.Email = strings.TrimSpace(profile.Email)
	profile.DisplayName = strings.TrimSpace(profile.DisplayName)
	profile.AvatarURL = strings.TrimSpace(profile.AvatarURL)
	ident = &profile
	existing, err := s.identities.FindByProviderUID(provider, ident.ProviderUserID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err
	}
	if existing != nil {
		if err := s.updateIdentityProfile(existing, ident); err != nil {
			return 0, err
		}
		if err := s.syncUserProfile(existing.UserID, provider, ident); err != nil {
			return 0, err
		}
		return existing.UserID, nil
	}

	created := &model.User{}
	if provider == "google" {
		googleID, email, picture, raw := ident.ProviderUserID, ident.Email, ident.AvatarURL, ident.RawIDToken
		created = &model.User{GoogleID: &googleID, Email: &email, Picture: &picture, OIDCToken: &raw}
	} else if ident.Email != "" {
		email := ident.Email
		created = &model.User{Email: &email}
	}
	if err := s.users.Create(created); err != nil {
		return 0, err
	}

	row := identityRow(provider, created.ID, ident)
	if err := s.identities.Create(row); err != nil {
		// Concurrent callback inserted the same identity first: fall back
		// to the update path (the user row just created is harmless).
		if repository.IsUniqueViolation(err) {
			slog.Warn("oauth upsert: identity insert lost the race, updating", "provider", provider)
			return s.UpsertByIdentity(ctx, provider, ident)
		}
		return 0, err
	}
	return created.ID, nil
}

func (s *UserService) updateIdentityProfile(row *model.UserIdentity, ident *Identity) error {
	cols := map[string]any{}
	if ident.Email != "" {
		cols["email"] = ident.Email
	}
	if ident.DisplayName != "" {
		cols["display_name"] = ident.DisplayName
	}
	if ident.AvatarURL != "" {
		cols["avatar_url"] = ident.AvatarURL
	}
	if len(cols) == 0 {
		return nil
	}
	return s.identities.UpdateProfile(row.ID, cols)
}

// Refresh the public /me profile for every provider. Missing fields must not
// clear saved data; the legacy Google token write remains Google-only.
func (s *UserService) syncUserProfile(userID int64, provider string, ident *Identity) error {
	cols := map[string]any{}
	if ident.Email != "" {
		cols["email"] = ident.Email
	}
	if ident.AvatarURL != "" {
		cols["picture"] = ident.AvatarURL
	}
	if provider == "google" {
		cols["oidc_token"] = ident.RawIDToken
	}
	if len(cols) == 0 {
		return nil
	}
	return s.users.Update(userID, cols)
}

func identityRow(provider string, userID int64, ident *Identity) *model.UserIdentity {
	row := &model.UserIdentity{
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: ident.ProviderUserID,
	}
	if ident.Email != "" {
		email := ident.Email
		row.Email = &email
	}
	if ident.DisplayName != "" {
		row.DisplayName = &ident.DisplayName
	}
	if ident.AvatarURL != "" {
		row.AvatarURL = &ident.AvatarURL
	}
	return row
}

func (s *UserService) GetByID(ctx context.Context, id int64) (*model.User, error) {
	return s.users.FindByID(id)
}

// ListIdentities returns the login identities of a user (/me additive field).
func (s *UserService) ListIdentities(ctx context.Context, userID int64) ([]model.UserIdentity, error) {
	return s.identities.ListByUser(userID)
}

// OIDCToken returns the user's stored Google id_token; the client WS channel
// forwards it to the device inside the offer frame (OidcGoogle field).
func (s *UserService) OIDCToken(ctx context.Context, id int64) (string, error) {
	u, err := s.users.FindByID(id)
	if err != nil {
		return "", err
	}
	if u.OIDCToken == nil {
		return "", nil
	}
	return *u.OIDCToken, nil
}

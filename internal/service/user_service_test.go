package service

import (
	"context"
	"errors"
	"testing"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
	"github.com/arkkvm/arkkvm-cloud-go/internal/repository"
)

// fakeUserStore / fakeIdentityStore implement the service-layer store
// interfaces in-memory.
type fakeUserStore struct {
	users   map[int64]*model.User
	nextID  int64
	updates map[int64]map[string]any
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{users: map[int64]*model.User{}, nextID: 100, updates: map[int64]map[string]any{}}
}

func (s *fakeUserStore) FindByID(id int64) (*model.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return u, nil
}

func (s *fakeUserStore) Create(u *model.User) error {
	s.nextID++
	u.ID = s.nextID
	cp := *u
	s.users[u.ID] = &cp
	return nil
}

func (s *fakeUserStore) Update(id int64, cols map[string]any) error {
	s.updates[id] = cols
	if u := s.users[id]; u != nil {
		for field, value := range cols {
			v := value.(string)
			switch field {
			case "email":
				u.Email = &v
			case "picture":
				u.Picture = &v
			case "oidc_token":
				u.OIDCToken = &v
			}
		}
	}
	return nil
}

func TestRepeatLoginBackfillsAndPreservesProfile(t *testing.T) {
	for _, provider := range []string{"apple", "google", "github", "microsoft", "wechat"} {
		t.Run(provider, func(t *testing.T) {
			users, identities := newFakeUserStore(), newFakeIdentityStore()
			svc := &UserService{users: users, identities: identities}
			ctx := context.Background()
			id, err := svc.UpsertByIdentity(ctx, provider, &Identity{ProviderUserID: "stable-sub"})
			if err != nil {
				t.Fatal(err)
			}
			profile := &Identity{ProviderUserID: "stable-sub", Email: " user@example.com ", DisplayName: " User Name ", AvatarURL: " https://img.test/avatar.png ", RawIDToken: "token"}
			for _, next := range []*Identity{profile, {ProviderUserID: "stable-sub"}, {ProviderUserID: "stable-sub", Email: "  ", DisplayName: "\t", AvatarURL: "\n"}} {
				gotID, err := svc.UpsertByIdentity(ctx, provider, next)
				if err != nil || gotID != id {
					t.Fatalf("repeat login changed account: id=%d err=%v", gotID, err)
				}
				row, _ := identities.FindByProviderUID(provider, "stable-sub")
				if row.DisplayName == nil || *row.DisplayName != "User Name" || row.Email == nil || *row.Email != "user@example.com" || row.AvatarURL == nil || *row.AvatarURL != "https://img.test/avatar.png" {
					t.Fatalf("identity profile missing/cleared: %+v", row)
				}
				u, _ := svc.GetByID(ctx, id)
				if u.Email == nil || *u.Email != "user@example.com" || u.Picture == nil || *u.Picture != "https://img.test/avatar.png" {
					t.Fatalf("public user profile missing/cleared: %+v", u)
				}
			}
			if len(users.users) != 1 || len(identities.rows) != 1 {
				t.Fatal("repeat authorization created an additional account")
			}
			if provider != "google" && users.users[id].OIDCToken != nil {
				t.Fatal("non-Google login wrote a Google token")
			}
			if profile.Email != " user@example.com " {
				t.Fatal("upsert mutated provider input")
			}
		})
	}
}

type fakeIdentityStore struct {
	rows     map[string]*model.UserIdentity // key provider|uid
	nextID   int64
	failOnce error // injected Create failure (unique-violation race)
}

func newFakeIdentityStore() *fakeIdentityStore {
	return &fakeIdentityStore{rows: map[string]*model.UserIdentity{}, nextID: 200}
}

func (s *fakeIdentityStore) FindByProviderUID(provider, uid string) (*model.UserIdentity, error) {
	row, ok := s.rows[provider+"|"+uid]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return row, nil
}

func (s *fakeIdentityStore) Create(row *model.UserIdentity) error {
	if s.failOnce != nil {
		err := s.failOnce
		s.failOnce = nil
		return err
	}
	key := row.Provider + "|" + row.ProviderUserID
	if _, exists := s.rows[key]; exists {
		return gorm.ErrDuplicatedKey
	}
	s.nextID++
	row.ID = s.nextID
	cp := *row
	s.rows[key] = &cp
	return nil
}

func (s *fakeIdentityStore) UpdateProfile(id int64, cols map[string]any) error {
	for _, row := range s.rows {
		if row.ID == id {
			for k, v := range cols {
				switch k {
				case "email":
					str := v.(string)
					row.Email = &str
				case "display_name":
					str := v.(string)
					row.DisplayName = &str
				case "avatar_url":
					str := v.(string)
					row.AvatarURL = &str
				}
			}
		}
	}
	return nil
}

func (s *fakeIdentityStore) ListByUser(userID int64) ([]model.UserIdentity, error) {
	var out []model.UserIdentity
	for _, row := range s.rows {
		if row.UserID == userID {
			out = append(out, *row)
		}
	}
	return out, nil
}

// --- tests ---

func googleIdent() *Identity {
	return &Identity{
		ProviderUserID: "g-sub-1",
		Email:          "u@example.com",
		EmailVerified:  true,
		AvatarURL:      "https://p/1.png",
		RawIDToken:     "raw-id-token",
	}
}

// Google identity hit: profile refreshed AND the legacy user row synced
// (picture/email/oidc_token double-write keeps /me googleId + offer frame).
func TestUpsertGoogleHitSyncsLegacyRow(t *testing.T) {
	users := newFakeUserStore()
	identities := newFakeIdentityStore()
	existing := &model.User{ID: 7}
	users.users[7] = existing
	identities.rows["google|g-sub-1"] = &model.UserIdentity{ID: 1, UserID: 7, Provider: "google", ProviderUserID: "g-sub-1"}

	svc := &UserService{users: users, identities: identities}
	id, err := svc.UpsertByIdentity(context.Background(), "google", googleIdent())
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if id != 7 {
		t.Fatalf("must reuse user 7, got %d", id)
	}
	cols := users.updates[7]
	if cols == nil || cols["oidc_token"] != "raw-id-token" || cols["email"] != "u@example.com" {
		t.Fatalf("legacy row must be synced for google, got %v", cols)
	}
	row, _ := identities.FindByProviderUID("google", "g-sub-1")
	if row.Email == nil || *row.Email != "u@example.com" {
		t.Fatalf("identity profile must be refreshed: %+v", row)
	}
}

// Google first login: user created with ALL legacy columns + identity row.
func TestUpsertGoogleCreate(t *testing.T) {
	users := newFakeUserStore()
	identities := newFakeIdentityStore()
	svc := &UserService{users: users, identities: identities}

	id, err := svc.UpsertByIdentity(context.Background(), "google", googleIdent())
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	u := users.users[id]
	if u == nil || u.GoogleID == nil || *u.GoogleID != "g-sub-1" ||
		u.OIDCToken == nil || *u.OIDCToken != "raw-id-token" {
		t.Fatalf("legacy columns must be filled: %+v", u)
	}
	row, err := identities.FindByProviderUID("google", "g-sub-1")
	if err != nil || row.UserID != id {
		t.Fatalf("identity row: %+v err=%v", row, err)
	}
}

// D1 conservative: a github identity with a verified email matching an
// existing user's email must NOT link — a fresh account is created.
func TestUpsertDoesNotLinkByEmail(t *testing.T) {
	users := newFakeUserStore()
	identities := newFakeIdentityStore()
	users.users[7] = &model.User{ID: 7}
	e := "same@example.com"
	users.users[7].Email = &e
	svc := &UserService{users: users, identities: identities}

	id, err := svc.UpsertByIdentity(context.Background(), "github", &Identity{
		ProviderUserID: "gh-1", Email: "same@example.com", EmailVerified: true, DisplayName: "GH",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if id == 7 {
		t.Fatal("D1 conservative: email match must NOT link to the existing account")
	}
	if u := users.users[id]; u == nil || u.Email == nil || *u.Email != "same@example.com" {
		t.Fatalf("email recorded for display on the new row: %+v", u)
	}
}

// WeChat: no email anywhere, independent account.
func TestUpsertWeChatIndependent(t *testing.T) {
	users := newFakeUserStore()
	identities := newFakeIdentityStore()
	svc := &UserService{users: users, identities: identities}

	id, err := svc.UpsertByIdentity(context.Background(), "wechat", &Identity{
		ProviderUserID: "u-union", DisplayName: "Wx", AvatarURL: "https://img",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if u := users.users[id]; u == nil || u.Email != nil || u.GoogleID != nil {
		t.Fatalf("wechat user row must stay empty of legacy columns: %+v", u)
	}
}

// Concurrent callback race: identity Create loses to a duplicate key — the
// upsert falls back to the existing row instead of failing the login.
func TestUpsertUniqueViolationRetries(t *testing.T) {
	users := newFakeUserStore()
	identities := newFakeIdentityStore()
	identities.rows["google|g-sub-1"] = &model.UserIdentity{ID: 1, UserID: 7, Provider: "google", ProviderUserID: "g-sub-1"}
	identities.failOnce = gorm.ErrDuplicatedKey // the racing insert won the unique key
	svc := &UserService{users: users, identities: identities}

	id, err := svc.UpsertByIdentity(context.Background(), "google", googleIdent())
	if err != nil {
		t.Fatalf("race must recover: %v", err)
	}
	if id != 7 {
		t.Fatalf("must resolve to the racing winner's user 7, got %d", id)
	}
	if users.updates[7] == nil {
		t.Fatal("retry path must still sync the legacy google row")
	}
}

// Regression guard for the dup detector itself (both recognition branches).
func TestIsUniqueViolation(t *testing.T) {
	if !repository.IsUniqueViolation(gorm.ErrDuplicatedKey) {
		t.Fatal("gorm.ErrDuplicatedKey must count")
	}
	if !repository.IsUniqueViolation(&mysql.MySQLError{Number: 1062}) {
		t.Fatal("raw mysql 1062 must count")
	}
	if repository.IsUniqueViolation(errors.New("other")) {
		t.Fatal("unrelated errors must not count")
	}
}

package repository

import (
	"errors"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"arkkvm.com/arkkvm-cloud/internal/model"
)

type IdentityRepo struct{ DB *gorm.DB }

func NewIdentityRepo(db *gorm.DB) *IdentityRepo { return &IdentityRepo{DB: db} }

// FindByProviderUID looks up an identity by its provider-scoped unique key.
func (r *IdentityRepo) FindByProviderUID(provider, providerUserID string) (*model.UserIdentity, error) {
	var id model.UserIdentity
	err := r.DB.Where("provider = ? AND provider_user_id = ?", provider, providerUserID).First(&id).Error
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (r *IdentityRepo) Create(id *model.UserIdentity) error { return r.DB.Create(id).Error }

// UpdateProfile refreshes only the display columns (email/display_name/avatar_url).
func (r *IdentityRepo) UpdateProfile(id int64, cols map[string]any) error {
	return r.DB.Model(&model.UserIdentity{}).Where("id = ?", id).Updates(cols).Error
}

func (r *IdentityRepo) ListByUser(userID int64) ([]model.UserIdentity, error) {
	var list []model.UserIdentity
	err := r.DB.Where("user_id = ?", userID).Order("id").Find(&list).Error
	return list, err
}

// IsUniqueViolation reports a duplicate (provider, provider_user_id) — the
// concurrent-login race where two callbacks insert the same new identity.
// Covers both the translated GORM error and the raw MySQL 1062.
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}

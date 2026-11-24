package repository

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"arkkvm.com/arkkvm-cloud/internal/model"
)

// McpTokenRepo persists mcp_tokens rows (doc 16 §2): lookup is always by
// token hash, never by user-facing fields.
type McpTokenRepo struct{ DB *gorm.DB }

func NewMcpTokenRepo(db *gorm.DB) *McpTokenRepo { return &McpTokenRepo{DB: db} }

func (r *McpTokenRepo) Create(t *model.McpToken) error { return r.DB.Create(t).Error }

// FindActiveByHash resolves a token hash to its non-revoked row.
func (r *McpTokenRepo) FindActiveByHash(hash string) (*model.McpToken, error) {
	var t model.McpToken
	err := r.DB.Where("token_hash = ? AND revoked_at IS NULL", hash).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, model.ErrMcpTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// TouchLastUsed refreshes the staleness marker in a single conditional
// UPDATE — at most once per minute, no read-back needed.
func (r *McpTokenRepo) TouchLastUsed(id int64, now time.Time) error {
	return r.DB.Model(&model.McpToken{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", id, now.Add(-time.Minute)).
		Update("last_used_at", now).Error
}

// Revoke marks the row revoked (idempotent: already-revoked rows stay put).
func (r *McpTokenRepo) Revoke(id int64, now time.Time) error {
	return r.DB.Model(&model.McpToken{}).
		Where("id = ? AND revoked_at IS NULL", id).
		Update("revoked_at", now).Error
}

func (r *McpTokenRepo) ListByUser(userID int64) ([]model.McpToken, error) {
	var list []model.McpToken
	err := r.DB.Where("user_id = ?", userID).Order("id").Find(&list).Error
	return list, err
}

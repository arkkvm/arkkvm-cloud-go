package model

import "time"

// UserIdentity maps to table "user_identities": one row per
// (provider, provider_user_id) login identity, linked to a user row.
// provider_user_id semantics: google/microsoft = OIDC sub, github = numeric
// REST id, wechat = unionid when present, else openid.
// Unlike the legacy "user" table this table DOES carry created_at/updated_at
// (both have DB defaults, so inserts work without setting them).
type UserIdentity struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID         int64     `gorm:"column:user_id;index:idx_identities_user"`
	Provider       string    `gorm:"column:provider;uniqueIndex:uk_provider_uid"`
	ProviderUserID string    `gorm:"column:provider_user_id;uniqueIndex:uk_provider_uid;size:191"`
	Email          *string   `gorm:"column:email"`
	DisplayName    *string   `gorm:"column:display_name"`
	AvatarURL      *string   `gorm:"column:avatar_url"`
	CreatedAt      time.Time `gorm:"column:created_at"`
	UpdatedAt      time.Time `gorm:"column:updated_at"`
}

func (UserIdentity) TableName() string { return "user_identities" }

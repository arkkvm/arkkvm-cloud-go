package model


// User maps to table "user" (explicit column names; the legacy schema used
// MyBatis-Plus camelCase-to-snake_case mapping).
// Note: user.id is int(11) in the current MySQL schema and will be upgraded
// to BIGINT during the PostgreSQL migration (doc 09 §3).
// The table has NO created_at/updated_at columns — do NOT add conventionally
// named timestamp fields, GORM would include them in INSERTs (this exact
// mismatch broke user upsert at first deploy).
type User struct {
	ID        int64   `gorm:"column:id;primaryKey;autoIncrement"`
	GoogleID  *string `gorm:"column:google_id"`
	Email     *string `gorm:"column:email"`
	Picture   *string `gorm:"column:picture"`
	OIDCToken *string `gorm:"column:oidc_token"`
}

func (User) TableName() string { return "user" }

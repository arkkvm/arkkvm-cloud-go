package model

import "time"

// McpToken maps to table "mcp_tokens": the first-class credential
// for the arkkvm_mcp host tool. Only the SHA-256 hex of the bearer token is
// stored — the plaintext is returned exactly once by POST /mcp/token. Tokens
// never expire on their own; revoked_at marks explicit revocation and
// last_used_at is the staleness marker.
type McpToken struct {
	ID         int64      `gorm:"column:id;primaryKey;autoIncrement"`
	UserID     int64      `gorm:"column:user_id;index:idx_mcp_tokens_user"`
	TokenHash  string     `gorm:"column:token_hash;uniqueIndex:uk_token_hash;size:64"`
	Name       string     `gorm:"column:name"`
	CreatedAt  time.Time  `gorm:"column:created_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at"`
	LastUsedAt *time.Time `gorm:"column:last_used_at"`
	RevokedAt  *time.Time `gorm:"column:revoked_at"`
}

func (McpToken) TableName() string { return "mcp_tokens" }

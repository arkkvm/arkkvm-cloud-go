package model

import "time"

// Device maps to table "device".
// BatchNo exists in the live schema (written by admin-api, not mapped by the
// legacy Java DO): it must be preserved and never cleared on updates.
// No created_at/updated_at columns exist — see the User model note.
type Device struct {
	ID           string     `gorm:"column:id;primaryKey"` // device-supplied primary key, varchar(32)
	UserID       int64      `gorm:"column:user_id"`
	Name         *string    `gorm:"column:name"`
	LastSeen     *time.Time `gorm:"column:last_seen"`
	SecretToken  *string    `gorm:"column:secret_token"`
	CloudVersion *string    `gorm:"column:cloud_version"`
	BatchNo      *string    `gorm:"column:batch_no"`
}

func (Device) TableName() string { return "device" }

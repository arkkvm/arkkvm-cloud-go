package model

import "time"

// TurnActivity maps to table "turn_activity".
// WARNING: this table's real column names are CAMELCASE (userId, bytesSent,
// bytesReceived, createdAt) — not snake_case — and the id column lacks
// AUTO_INCREMENT while bytes columns are NOT NULL without defaults. Insert
// path was broken in the legacy Java deployment too (0 rows despite usage;
// MyBatis-Plus generated snake_case columns that don't exist). Column tags
// here match reality; the id problem is flagged in — the table
// needs a one-line ALTER (AUTO_INCREMENT) or a rebuild in the PG migration.
type TurnActivity struct {
	ID            int64     `gorm:"column:id;primaryKey"`
	UserID        int64     `gorm:"column:userId"`
	BytesSent     int64     `gorm:"column:bytesSent"`
	BytesReceived int64     `gorm:"column:bytesReceived"`
	CreatedAt     time.Time `gorm:"column:createdAt"`
}

func (TurnActivity) TableName() string { return "turn_activity" }

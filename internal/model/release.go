package model

// Release maps to table "releases" (deployed-branch schema, verified on the
// test environment).
// DeviceSNs is a comma-separated device SN allowlist (used by distribution=1,
// internal testing), stored as raw TEXT and parsed in the service layer.
// SortOrder is a legacy column used by the master branch; the deployed branch
// no longer compares against it, it is kept for archival purposes only.
type Release struct {
	ID           int64   `gorm:"column:id;primaryKey;autoIncrement"`
	Version      string  `gorm:"column:version"`
	URL          string  `gorm:"column:url"`
	Hash         string  `gorm:"column:hash"`
	Type         string  `gorm:"column:type"` // app | system
	Summary      *string `gorm:"column:summary"`
	Gray         *int    `gorm:"column:gray"`
	Distribution *int    `gorm:"column:distribution"` // 1 internal | 2 gray rollout | 3 full rollout
	DeviceSNs    *string `gorm:"column:device_sns"`
	IsPreview    *bool   `gorm:"column:is_preview"`
	SortOrder    *int64  `gorm:"column:sort_order"`
	Major        int     `gorm:"column:major"`
	Minor        int     `gorm:"column:minor"`
	Patch        int64   `gorm:"column:patch"`
}

func (Release) TableName() string { return "releases" }

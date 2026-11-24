package repository

import (
	"arkkvm.com/arkkvm-cloud/internal/model"
	"gorm.io/gorm"
)

type ReleaseRepo struct{ DB *gorm.DB }

func NewReleaseRepo(db *gorm.DB) *ReleaseRepo { return &ReleaseRepo{DB: db} }

// ListByTypeOrdered implements the deployed-branch semantics: return all rows
// of the type ordered by major/minor/patch descending; distribution rules
// (distribution/device_sns/gray) are evaluated in the service layer (doc 02 §1.4).
func (r *ReleaseRepo) ListByTypeOrdered(releaseType string) ([]model.Release, error) {
	var list []model.Release
	err := r.DB.
		Where("type = ?", releaseType).
		Order("major DESC").Order("minor DESC").Order("patch DESC").
		Find(&list).Error
	return list, err
}

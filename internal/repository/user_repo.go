package repository

import (
	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
	"gorm.io/gorm"
)

type UserRepo struct{ DB *gorm.DB }

func NewUserRepo(db *gorm.DB) *UserRepo { return &UserRepo{DB: db} }

func (r *UserRepo) FindByID(id int64) (*model.User, error) {
	var u model.User
	err := r.DB.First(&u, id).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) Create(u *model.User) error { return r.DB.Create(u).Error }

// Update writes only the given columns (never full-row Save, to avoid clearing
// fields maintained by admin-api).
func (r *UserRepo) Update(id int64, cols map[string]any) error {
	return r.DB.Model(&model.User{}).Where("id = ?", id).Updates(cols).Error
}

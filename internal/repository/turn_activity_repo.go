package repository

import (
	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
	"gorm.io/gorm"
)

type TurnActivityRepo struct{ DB *gorm.DB }

func NewTurnActivityRepo(db *gorm.DB) *TurnActivityRepo { return &TurnActivityRepo{DB: db} }

func (r *TurnActivityRepo) Create(t *model.TurnActivity) error { return r.DB.Create(t).Error }

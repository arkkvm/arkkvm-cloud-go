package repository

import (
	"context"
	"time"

	"arkkvm.com/arkkvm-cloud/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type DeviceRepo struct{ DB *gorm.DB }

func NewDeviceRepo(db *gorm.DB) *DeviceRepo { return &DeviceRepo{DB: db} }

func (r *DeviceRepo) FindByID(id string) (*model.Device, error) {
	var d model.Device
	err := r.DB.First(&d, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *DeviceRepo) FindBySecretToken(token string) (*model.Device, error) {
	var d model.Device
	err := r.DB.First(&d, "secret_token = ?", token).Error
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *DeviceRepo) FindByIDAndUser(id string, userID int64) (*model.Device, error) {
	var d model.Device
	err := r.DB.First(&d, "id = ? AND user_id = ?", id, userID).Error
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// FindByIDAndSecret locates a device by id + secret_token (device-side
// self-authenticated unbind, DELETE /devices/{id}).
func (r *DeviceRepo) FindByIDAndSecret(id, secretToken string) (*model.Device, error) {
	var d model.Device
	err := r.DB.First(&d, "id = ? AND secret_token = ?", id, secretToken).Error
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *DeviceRepo) ListByUser(userID int64) ([]model.Device, error) {
	var list []model.Device
	err := r.DB.Where("user_id = ?", userID).Find(&list).Error
	return list, err
}

func (r *DeviceRepo) Create(d *model.Device) error { return r.DB.Create(d).Error }

// CompleteBinding writes ownership and credential together. The primary key
// resolves simultaneous first claims, and the row lock protects an existing
// binding from a concurrent rebind/unbind. Never overwrite another owner.
func (r *DeviceRepo) CompleteBinding(ctx context.Context, id string, userID int64, secret string, previousSecret *string, allowCreate bool) (bool, error) {
	ok := false
	err := r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if allowCreate {
			candidate := model.Device{ID: id, UserID: userID, SecretToken: &secret}
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "id"}}, DoNothing: true,
			}).Create(&candidate).Error; err != nil {
				return err
			}
		}
		var current model.Device
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&current, "id = ?", id).Error; err != nil {
			return err
		}
		if current.UserID != userID {
			return nil
		}
		if current.SecretToken != nil && *current.SecretToken == secret {
			ok = true // response-loss retry: keep the exact committed credential
			return nil
		}
		if previousSecret == nil || !sameSecret(current.SecretToken, previousSecret) {
			return nil // a newer pairing has already replaced the snapshot
		}
		if err := tx.Model(&model.Device{}).Where("id = ? AND user_id = ?", id, userID).
			Update("secret_token", secret).Error; err != nil {
			return err
		}
		ok = true
		return nil
	})
	return ok && err == nil, err
}

func sameSecret(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (r *DeviceRepo) Delete(id string) error { return r.DB.Delete(&model.Device{}, "id = ?", id).Error }

// Update writes only the given columns (protects batch_no and other fields
// maintained by admin-api).
func (r *DeviceRepo) Update(id string, cols map[string]any) error {
	return r.DB.Model(&model.Device{}).Where("id = ?", id).Updates(cols).Error
}

func (r *DeviceRepo) UpdateLastSeen(id string) error {
	return r.Update(id, map[string]any{"last_seen": time.Now()})
}

func (r *DeviceRepo) ExistsForUser(id string, userID int64) (bool, error) {
	var n int64
	err := r.DB.Model(&model.Device{}).Where("id = ? AND user_id = ?", id, userID).Count(&n).Error
	return n > 0, err
}

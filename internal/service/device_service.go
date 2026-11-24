package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"gorm.io/gorm"

	"arkkvm.com/arkkvm-cloud/internal/auth"
	"arkkvm.com/arkkvm-cloud/internal/model"
	"arkkvm.com/arkkvm-cloud/internal/repository"
)

// DevicePresence abstracts the in-memory WebSocket state so the service layer
// does not depend on the ws package (dependency direction: ws -> service).
// Implemented by ws.Hub.
type DevicePresence interface {
	IsOnline(deviceID string) bool
	// CloseDevice kicks the device's WebSocket connection, returning whether
	// one existed (used by cloud-side unbind).
	CloseDevice(deviceID string) bool
}

type DeviceService struct {
	devices  *repository.DeviceRepo
	presence DevicePresence
}

func NewDeviceService(devices *repository.DeviceRepo, presence DevicePresence) *DeviceService {
	return &DeviceService{devices: devices, presence: presence}
}

var (
	ErrDeviceNotFound     = errors.New("device not found")
	ErrDeviceAlreadyBound = errors.New("Device already bound")
)

// PrepareDevicePairing checks ownership without modifying a device. Capture
// the current credential so a stale retry cannot overwrite a later re-pairing.
func (s *DeviceService) PrepareDevicePairing(ctx context.Context, deviceID string, userID int64) (*string, error) {
	existing, err := s.devices.FindByID(deviceID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if existing.UserID != userID {
		// Keep the ownership guard; only expose a minimal, masked account hint.
		hint, _ := s.boundAccountHint(ctx, existing.UserID)
		return nil, &DeviceBindingConflict{BoundAccount: hint}
	}
	return nil, &DeviceBindingConflict{}
}

func (s *DeviceService) HasDevice(ctx context.Context, deviceID string, userID int64) (bool, error) {
	return s.devices.ExistsForUser(deviceID, userID)
}

func (s *DeviceService) GetDevice(ctx context.Context, deviceID string, userID int64) (*model.Device, error) {
	return s.devices.FindByIDAndUser(deviceID, userID)
}

// GetByID fetches a device by primary key without an ownership filter
// (quick login resolves the owner FROM the device row).
func (s *DeviceService) GetByID(ctx context.Context, deviceID string) (*model.Device, error) {
	return s.devices.FindByID(deviceID)
}

func (s *DeviceService) ListDevices(ctx context.Context, userID int64) ([]model.Device, error) {
	return s.devices.ListByUser(userID)
}

func (s *DeviceService) UpdateDevice(ctx context.Context, deviceID string, userID int64, name string) error {
	if _, err := s.devices.FindByIDAndUser(deviceID, userID); err != nil {
		return err
	}
	return s.devices.Update(deviceID, map[string]any{"name": name})
}

// UnbindDevice is the device-side delete: the caller authenticates with the
// device secretToken itself (DELETE /devices/{id}).
func (s *DeviceService) UnbindDevice(ctx context.Context, deviceID, secretToken string) error {
	dev, err := s.devices.FindByIDAndSecret(deviceID, secretToken)
	if err != nil {
		return err
	}
	if err := s.devices.Delete(dev.ID); err != nil {
		return err
	}
	s.presence.CloseDevice(dev.ID)
	return nil
}

// DeleteDevice is the cloud-side unbind: ownership check, delete the row,
// then kick the online device connection (legacy deleteDevice behavior).
func (s *DeviceService) DeleteDevice(ctx context.Context, deviceID string, userID int64) error {
	if _, err := s.devices.FindByIDAndUser(deviceID, userID); err != nil {
		return err
	}
	if err := s.devices.Delete(deviceID); err != nil {
		return err
	}
	s.presence.CloseDevice(deviceID)
	return nil
}

func (s *DeviceService) UpdateLastSeen(ctx context.Context, deviceID string) {
	_ = s.devices.UpdateLastSeen(deviceID)
}

func (s *DeviceService) IsOnline(deviceID string) bool {
	return s.presence.IsOnline(deviceID)
}

// FindBySecretToken resolves a permanent device token (device WS handshake).
func (s *DeviceService) FindBySecretToken(ctx context.Context, secretToken string) (string, *string, error) {
	dev, err := s.devices.FindBySecretToken(secretToken)
	if err != nil {
		return "", nil, err
	}
	return dev.ID, dev.CloudVersion, nil
}

// UpdateCloudVersion persists a changed version reported at handshake.
func (s *DeviceService) UpdateCloudVersion(ctx context.Context, deviceID, cloudVersion string) error {
	return s.devices.Update(deviceID, map[string]any{"cloud_version": cloudVersion})
}

// BelongsToUser checks device ownership (client WS handshake).
func (s *DeviceService) BelongsToUser(ctx context.Context, deviceID string, userID int64) (bool, error) {
	return s.devices.ExistsForUser(deviceID, userID)
}

// deviceTokenService accepts only explicit confirmation tokens, never an
// OAuth callback token or a legacy device-shaped login session.
type deviceTokenService interface {
	ExchangeProtectedPairingToken(ctx context.Context, token, requestID, verifier string) (*auth.DevicePairing, error)
}

// ExchangeDeviceToken is the cloud step of the existing device /cloud/register
// flow. Validate the Redis confirmation, then commit ownership and credential
// together. Retries use the same credential and cannot roll back a later one.
func (s *DeviceService) ExchangeDeviceToken(ctx context.Context, tokens deviceTokenService, tempToken, requestID, verifier string) (string, int64, error) {
	p, err := tokens.ExchangeProtectedPairingToken(ctx, tempToken, requestID, verifier)
	if err != nil {
		return "", 0, err
	}
	ok, err := s.devices.CompleteBinding(ctx, p.DeviceID, p.UserID, p.SecretToken, p.PreviousSecret, !p.Attempted)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return "", 0, ErrDeviceAlreadyBound
	}
	return p.SecretToken, p.UserID, nil
}

// WebVersionFromCloudVersion implements the deployed-branch compatibility:
// new devices report cloud_version as JSON {"webVersion": "..."} while old
// devices report a plain string. The API always surfaces the plain webVersion.
func WebVersionFromCloudVersion(cloudVersion *string) string {
	if cloudVersion == nil || *cloudVersion == "" {
		return ""
	}
	raw := *cloudVersion
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") && json.Valid([]byte(trimmed)) {
		var payload struct {
			WebVersion string `json:"webVersion"`
		}
		if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
			return payload.WebVersion
		}
	}
	return raw
}

package service

import (
	"context"
	"strings"

	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
)

// BoundAccountHint is for recognizing an existing owner, never authenticating
// as that owner. Do not add IDs, raw names/emails, avatars or credentials here.
type BoundAccountHint struct {
	Provider          string  `json:"provider"`
	MaskedEmail       *string `json:"maskedEmail"`
	MaskedDisplayName *string `json:"maskedDisplayName"`
}

type DeviceBindingConflict struct {
	BoundAccount *BoundAccountHint
}

func (e *DeviceBindingConflict) Error() string { return ErrDeviceAlreadyBound.Error() }
func (e *DeviceBindingConflict) Unwrap() error { return ErrDeviceAlreadyBound }

func (s *DeviceService) boundAccountHint(ctx context.Context, userID int64) (*BoundAccountHint, error) {
	var identities []model.UserIdentity
	if err := s.devices.DB.WithContext(ctx).Select("provider", "email", "display_name").
		Where("user_id = ?", userID).Order("id").Find(&identities).Error; err != nil {
		return nil, err
	}
	hint := &BoundAccountHint{}
	if len(identities) > 0 {
		identity := identities[0]
		hint.Provider = identity.Provider
		hint.MaskedEmail = maskedAccountEmail(identity.Email)
		hint.MaskedDisplayName = maskedAccountName(identity.DisplayName)
	}
	if hint.MaskedEmail == nil {
		var user model.User
		if err := s.devices.DB.WithContext(ctx).Select("id", "email").First(&user, userID).Error; err != nil {
			// Still return the provider/name hint if the legacy row is missing.
			if len(identities) > 0 {
				return hint, nil
			}
			return nil, err
		}
		hint.MaskedEmail = maskedAccountEmail(user.Email)
	}
	return hint, nil
}

func maskedAccountEmail(email *string) *string {
	if email == nil {
		return nil
	}
	value := strings.TrimSpace(*email)
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return nil
	}
	local := []rune(value[:at])
	masked := string(local[0]) + "***@" + value[at+1:]
	return &masked
}

func maskedAccountName(name *string) *string {
	if name == nil {
		return nil
	}
	runes := []rune(strings.TrimSpace(*name))
	if len(runes) == 0 {
		return nil
	}
	masked := "***"
	if len(runes) > 1 {
		masked = string(runes[0]) + "***"
	}
	return &masked
}

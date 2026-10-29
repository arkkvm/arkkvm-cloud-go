package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
	"github.com/arkkvm/arkkvm-cloud-go/internal/pkg"
	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
)

// UserHandler serves GET /me and GET /logout.
type UserHandler struct {
	users  *service.UserService
	tokens *auth.TokenService
}

func NewUserHandler(users *service.UserService, tokens *auth.TokenService) *UserHandler {
	return &UserHandler{users: users, tokens: tokens}
}

// userView is the /me payload. Field names match the legacy UserDO
// serialization; oidcToken is stripped unless expose-sensitive-fields is on
// (, default stripped). identities is additive: the
// login identities of the account, googleId and friends stay untouched.
type userView struct {
	ID       int64   `json:"id"`
	GoogleID *string `json:"googleId"`
	Email    *string `json:"email"`
	// Accounts currently resolve by provider identity, without email linking.
	// Do not guess an active provider for legacy accounts with multiple identities.
	Provider *string `json:"provider"`
	// DisplayName surfaces the first non-empty identity display name (e.g.
	// the WeChat nickname) — email-less providers otherwise render an empty
	// account block in the console.
	DisplayName *string        `json:"displayName"`
	Picture     *string        `json:"picture"`
	OIDCToken   *string        `json:"oidcToken"`
	Identities  []identityView `json:"identities"`
}

type identityView struct {
	Provider    string  `json:"provider"`
	Email       *string `json:"email"`
	DisplayName *string `json:"displayName"`
	AvatarURL   *string `json:"avatarUrl"`
}

func (h *UserHandler) Me(c *gin.Context) {
	user, err := h.users.GetByID(c.Request.Context(), auth.UserID(c))
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "user lookup failed")
		return
	}
	view := userView{
		ID:       user.ID,
		GoogleID: user.GoogleID,
		Email:    user.Email,
		Picture:  user.Picture,
	}
	identities, err := h.users.ListIdentities(c.Request.Context(), user.ID)
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "identity lookup failed")
		return
	}
	view.Identities = make([]identityView, 0, len(identities)) // nil-safe: []
	if len(identities) == 1 {
		provider := identities[0].Provider
		view.Provider = &provider
	}
	for i := range identities {
		if !hasProfileValue(view.DisplayName) && hasProfileValue(identities[i].DisplayName) {
			name := *identities[i].DisplayName
			view.DisplayName = &name
		}
		// Older non-Google accounts may only have profile data in identities.
		if !hasProfileValue(view.Email) && hasProfileValue(identities[i].Email) {
			view.Email = identities[i].Email
		}
		if !hasProfileValue(view.Picture) && hasProfileValue(identities[i].AvatarURL) {
			view.Picture = identities[i].AvatarURL
		}
		view.Identities = append(view.Identities, identityView{
			Provider:    identities[i].Provider,
			Email:       identities[i].Email,
			DisplayName: identities[i].DisplayName,
			AvatarURL:   identities[i].AvatarURL,
		})
	}
	if exposeSensitive {
		view.OIDCToken = user.OIDCToken
	}
	OK(c, view)
}

func hasProfileValue(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func (h *UserHandler) Logout(c *gin.Context) {
	token := auth.BearerToken(c.GetHeader("Authorization"))
	if err := h.tokens.Logout(c.Request.Context(), token); err != nil {
		FailCode(c, http.StatusInternalServerError, "logout failed")
		return
	}
	OKEmpty(c)
}

// deviceView is the list item of GET /devices (DeviceVO parity).
type deviceView struct {
	ID           string        `json:"id"`
	Name         *string       `json:"name"`
	LastSeen     *pkg.JsonTime `json:"lastSeen"`
	Online       bool          `json:"online"`
	CloudVersion string        `json:"cloudVersion"`
}

// deviceDetailView is the DeviceDO-shaped response of GET /devices/{id} and
// PUT /devices/{id}; secretToken is stripped by default.
type deviceDetailView struct {
	ID           string        `json:"id"`
	UserID       int64         `json:"userId"`
	Name         *string       `json:"name"`
	LastSeen     *pkg.JsonTime `json:"lastSeen"`
	SecretToken  *string       `json:"secretToken"`
	CloudVersion *string       `json:"cloudVersion"`
}

// DeviceHandler serves the /devices endpoints.
type DeviceHandler struct {
	devices *service.DeviceService
	tokens  *auth.TokenService
}

func NewDeviceHandler(devices *service.DeviceService, tokens *auth.TokenService) *DeviceHandler {
	return &DeviceHandler{devices: devices, tokens: tokens}
}

// Bind checks the selected account, then stages a pairing in Redis only.
func (h *DeviceHandler) Bind(c *gin.Context) {
	deviceID := c.Param("id")
	if len(deviceID) == 0 || len(deviceID) > 32 {
		Fail(c, "invalid deviceId")
		return
	}
	userID := auth.UserID(c)
	previousSecret, err := h.devices.PrepareDevicePairing(c.Request.Context(), deviceID, userID)
	if err != nil {
		if errors.Is(err, service.ErrDeviceAlreadyBound) {
			var conflict *service.DeviceBindingConflict
			var account *service.BoundAccountHint
			if errors.As(err, &conflict) {
				account = conflict.BoundAccount
			}
			c.JSON(http.StatusOK, BaseResult[any]{
				Success: false, Message: service.ErrDeviceAlreadyBound.Error(), Code: 0,
				Data: gin.H{
					"reason": "DEVICE_ALREADY_BOUND", "boundAccount": account,
					"action": "SIGN_IN_AS_BOUND_ACCOUNT_AND_UNBIND",
				},
			})
		} else {
			FailCode(c, http.StatusInternalServerError, "check device failed")
		}
		return
	}
	tempToken, err := h.tokens.IssueConfirmedPairingToken(c.Request.Context(), userID, deviceID, previousSecret)
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "pairing token mint failed")
		return
	}
	OK(c, gin.H{"deviceId": deviceID, "tempToken": tempToken})
}

func (h *DeviceHandler) List(c *gin.Context) {
	list, err := h.devices.ListDevices(c.Request.Context(), auth.UserID(c))
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "list devices failed")
		return
	}
	views := make([]deviceView, 0, len(list)) // nil-safe: empty slice marshals as []
	for i := range list {
		d := &list[i]
		views = append(views, deviceView{
			ID:           d.ID,
			Name:         d.Name,
			LastSeen:     jsonTimePtr(d.LastSeen),
			Online:       h.devices.IsOnline(d.ID),
			CloudVersion: service.WebVersionFromCloudVersion(d.CloudVersion),
		})
	}
	OK(c, views)
}

func (h *DeviceHandler) Get(c *gin.Context) {
	d, err := h.devices.GetDevice(c.Request.Context(), c.Param("id"), auth.UserID(c))
	if err != nil {
		Fail(c, service.ErrDeviceNotFound.Error())
		return
	}
	view := deviceDetailView{
		ID:           d.ID,
		UserID:       d.UserID,
		Name:         d.Name,
		LastSeen:     jsonTimePtr(d.LastSeen),
		CloudVersion: d.CloudVersion,
	}
	if exposeSensitive {
		view.SecretToken = d.SecretToken
	}
	OK(c, view)
}

type updateDeviceRequest struct {
	Name string `json:"name" binding:"required,min=3,max=20"`
}

func (h *DeviceHandler) Update(c *gin.Context) {
	var req updateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		FailCode(c, http.StatusInternalServerError, "invalid device name (3-20 chars)")
		return
	}
	if err := h.devices.UpdateDevice(c.Request.Context(), c.Param("id"), auth.UserID(c), req.Name); err != nil {
		Fail(c, service.ErrDeviceNotFound.Error())
		return
	}
	h.Get(c)
}

// Unbind is the device-side DELETE /devices/{id}: the caller authenticates
// with the device secretToken itself (no login required).
func (h *DeviceHandler) Unbind(c *gin.Context) {
	token := auth.BearerToken(c.GetHeader("Authorization"))
	if token == "" {
		Fail(c, "Authorization header is missing or invalid")
		return
	}
	if err := h.devices.UnbindDevice(c.Request.Context(), c.Param("id"), token); err != nil {
		Fail(c, service.ErrDeviceNotFound.Error())
		return
	}
	OKEmpty(c)
}

// CloudUnbind is DELETE /cloud/devices/{id}: ownership-checked delete plus a
// kick of the online device connection.
func (h *DeviceHandler) CloudUnbind(c *gin.Context) {
	if err := h.devices.DeleteDevice(c.Request.Context(), c.Param("id"), auth.UserID(c)); err != nil {
		Fail(c, service.ErrDeviceNotFound.Error())
		return
	}
	OKEmpty(c)
}

// ExchangeToken is POST /devices/token: confirmed tempToken -> permanent
// secretToken. Successful validation commits the device binding atomically.
// The response is a bare JSON object (no BaseResult envelope).
// userId is additive (de-providerized firmware stores owner_user_id);
// legacy firmware ignores the extra field.
func (h *DeviceHandler) ExchangeToken(c *gin.Context) {
	var req struct {
		TempToken string `json:"tempToken" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		FailCode(c, http.StatusInternalServerError, "tempToken is required")
		return
	}
	secret, userID, err := h.devices.ExchangeDeviceToken(c.Request.Context(), h.tokens, req.TempToken)
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "invalid or expired confirmed pairing token")
		return
	}
	c.JSON(http.StatusOK, gin.H{"secretToken": secret, "userId": userID})
}

func jsonTimePtr(t *time.Time) *pkg.JsonTime {
	if t == nil {
		return nil
	}
	jt := pkg.JsonTime(*t)
	return &jt
}

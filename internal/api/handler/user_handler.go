package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"arkkvm.com/arkkvm-cloud/internal/auth"
	"arkkvm.com/arkkvm-cloud/internal/pkg"
	"arkkvm.com/arkkvm-cloud/internal/service"
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
// (doc 06 §5, default stripped). identities is additive (doc 14 §4): the
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
	if token := auth.SessionToken(c); token != "" {
		c.Header(auth.SessionReferenceHeader, auth.BrowserSessionReference(token))
	}
	OK(c, view)
}

func hasProfileValue(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func (h *UserHandler) Logout(c *gin.Context) {
	token := auth.SessionToken(c)
	if err := h.tokens.Logout(c.Request.Context(), token); err != nil {
		FailCode(c, http.StatusInternalServerError, "logout failed")
		return
	}
	auth.ClearBrowserSessionCookie(c.Writer)
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
// PUT /devices/{id}; secretToken is stripped by default (doc 06 §5).
type deviceDetailView struct {
	ID           string        `json:"id"`
	UserID       int64         `json:"userId"`
	Name         *string       `json:"name"`
	LastSeen     *pkg.JsonTime `json:"lastSeen"`
	SecretToken  *string       `json:"secretToken"`
	CloudVersion *string       `json:"cloudVersion"`
}

// DeviceHandler serves the /devices endpoints (doc 02 §1.2).
type DeviceHandler struct {
	devices *service.DeviceService
	tokens  *auth.TokenService
	proxies *pkg.TrustedProxies
}

func NewDeviceHandler(devices *service.DeviceService, tokens *auth.TokenService, policies ...*pkg.TrustedProxies) *DeviceHandler {
	h := &DeviceHandler{devices: devices, tokens: tokens}
	if len(policies) == 1 {
		h.proxies = policies[0]
	}
	return h
}

// Bind checks the selected account, then stages a pairing in Redis only.
func (h *DeviceHandler) Bind(c *gin.Context) {
	deviceID := c.Param("id")
	if len(deviceID) == 0 || len(deviceID) > 32 {
		Fail(c, "invalid deviceId")
		return
	}
	var req struct {
		RequestID string `json:"requestId"`
		Confirm   bool   `json:"confirm"`
	}
	if c.ShouldBindJSON(&req) != nil || !req.Confirm {
		FailCode(c, http.StatusBadRequest, "firmware upgrade required")
		return
	}
	pending, err := h.tokens.BindingRequest(c.Request.Context(), req.RequestID)
	if err != nil || pending.DeviceID != deviceID {
		FailCode(c, http.StatusBadRequest, "binding request expired")
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
	// Binding an already provisioned device requires explicit unbinding first,
	// including for the same owner. Never silently rotate its credential.
	if previousSecret != nil {
		FailCode(c, http.StatusConflict, "device must be unbound first")
		return
	}
	pairing, err := h.tokens.ApproveBinding(c.Request.Context(), pending, userID)
	if err != nil {
		FailCode(c, http.StatusInternalServerError, "pairing token mint failed")
		return
	}
	c.Header("Cache-Control", "no-store")
	OK(c, gin.H{"deviceId": deviceID, "requestId": pending.RequestID, "deviceReturnTo": pending.ReturnTo, "tempToken": pairing.TempToken})
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
// userId is additive (de-providerized firmware stores owner_user_id, doc 05
// §2.1); legacy firmware ignores the extra field.
func (h *DeviceHandler) ExchangeToken(c *gin.Context) {
	var req struct {
		TempToken    string `json:"tempToken" binding:"required"`
		RequestID    string `json:"requestId" binding:"required"`
		CodeVerifier string `json:"codeVerifier" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		FailCode(c, http.StatusBadRequest, "binding proof is required")
		return
	}
	secret, userID, err := h.devices.ExchangeDeviceToken(c.Request.Context(), h.tokens, req.TempToken, req.RequestID, req.CodeVerifier)
	if err != nil {
		FailCode(c, http.StatusUnauthorized, "invalid or expired confirmed pairing token")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"secretToken": secret, "userId": userID})
}

func jsonTimePtr(t *time.Time) *pkg.JsonTime {
	if t == nil {
		return nil
	}
	jt := pkg.JsonTime(*t)
	return &jt
}

// Only literal LAN addresses or mDNS names are eligible device callbacks.
// No DNS resolution or server-side request is performed for this address.
func validDeviceCallback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/ad-login" || u.RawPath != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsPrivate() && ip.Zone() == ""
	}
	return regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.local$`).MatchString(host)
}
func (h *DeviceHandler) CreateBindingRequest(c *gin.Context) {
	if !h.tokens.AllowBindingRequest(c.Request.Context(), pkg.RealIP(c.Request, h.proxies)) {
		FailCode(c, 429, "too many binding requests")
		return
	}
	var req struct {
		DeviceID  string `json:"deviceId"`
		ReturnTo  string `json:"deviceReturnTo"`
		Challenge string `json:"challenge"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2048)
	if c.ShouldBindJSON(&req) != nil || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`).MatchString(req.DeviceID) || !validDeviceCallback(req.ReturnTo) {
		FailCode(c, 400, "invalid binding request")
		return
	}
	b, err := base64.RawURLEncoding.DecodeString(req.Challenge)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != req.Challenge {
		FailCode(c, 400, "invalid challenge")
		return
	}
	p, err := h.tokens.CreateBindingRequest(c.Request.Context(), req.DeviceID, req.ReturnTo, req.Challenge)
	if err != nil {
		FailCode(c, 503, "binding request unavailable")
		return
	}
	c.Header("Cache-Control", "no-store")
	OK(c, gin.H{"requestId": p.RequestID, "expiresIn": 300})
}
func (h *DeviceHandler) BindingRequest(c *gin.Context) {
	p, err := h.tokens.BindingRequest(c.Request.Context(), c.Param("requestId"))
	if err != nil {
		FailCode(c, 404, "binding request expired")
		return
	}
	c.Header("Cache-Control", "no-store")
	OK(c, gin.H{"requestId": p.RequestID, "deviceId": p.DeviceID, "deviceReturnTo": p.ReturnTo})
}

// BindingRequestStatus exposes only protocol readiness, never device details or proof.
func (h *DeviceHandler) BindingRequestStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(c.Param("requestId")) {
		FailCode(c, 400, "invalid binding request")
		return
	}
	if !h.tokens.AllowBindingStatus(c.Request.Context(), pkg.RealIP(c.Request, h.proxies)) {
		FailCode(c, 429, "too many binding status requests")
		return
	}
	if _, err := h.tokens.BindingRequest(c.Request.Context(), c.Param("requestId")); err != nil {
		FailCode(c, 404, "binding request expired")
		return
	}
	OK(c, gin.H{"status": "ready"})
}

package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
)

// ReleaseHandler serves GET /releases (deployed-branch
// semantics). The response is the bare ReleaseRetrieveVO — no BaseResult
// envelope — with null fields when no update applies.
type ReleaseHandler struct {
	releases *service.ReleaseService
}

func NewReleaseHandler(releases *service.ReleaseService) *ReleaseHandler {
	return &ReleaseHandler{releases: releases}
}

func (h *ReleaseHandler) Retrieve(c *gin.Context) {
	vo, err := h.releases.Retrieve(
		c.Request.Context(),
		c.Query("appVersion"),
		c.Query("systemVersion"),
		c.Query("deviceId"),
	)
	if err != nil {
		// Legacy parity: invalid version input surfaced as the global
		// exception path (HTTP 200 + code 500 + message).
		FailCode(c, http.StatusInternalServerError, err.Error())
		return
	}
	c.JSON(http.StatusOK, vo)
}

package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"arkkvm.com/arkkvm-cloud/internal/service"
)

// ReleaseHandler serves GET /releases (doc 02 §1.4, deployed-branch
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
		FailCode(c, http.StatusInternalServerError, "Unable to retrieve release information")
		return
	}
	c.JSON(http.StatusOK, vo)
}

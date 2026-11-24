package handler

import (
	"net/http"
	"net/netip"

	"arkkvm.com/arkkvm-cloud/internal/pkg"
	"arkkvm.com/arkkvm-cloud/internal/service"
	"github.com/gin-gonic/gin"
)

type ipLocator interface {
	Lookup(netip.Addr) (service.IPLocation, error)
}

type IPHandler struct {
	locator ipLocator
	trusted *pkg.TrustedProxies
}

func NewIPHandler(locator ipLocator, trustedProxies []string) (*IPHandler, error) {
	trusted, err := pkg.NewTrustedProxies(trustedProxies)
	if err != nil {
		return nil, err
	}
	return &IPHandler{locator: locator, trusted: trusted}, nil
}

func (h *IPHandler) clientIP(r *http.Request) netip.Addr { return h.trusted.ClientIP(r) }

func (h *IPHandler) Get(c *gin.Context) {
	ip := h.clientIP(c.Request)
	view := struct {
		IP       string `json:"ip"`
		IsPublic bool   `json:"isPublic"`
		service.IPLocation
	}{IsPublic: service.IsPublicIP(ip)}
	if ip.IsValid() {
		view.IP = ip.String()
	}
	if h.locator != nil && view.IsPublic {
		location, err := h.locator.Lookup(ip)
		if err == nil {
			view.IPLocation = location
		}
	}
	// A shared cache must never serve another visitor's IP/location.
	c.Header("Cache-Control", "no-store")
	OK(c, view)
}

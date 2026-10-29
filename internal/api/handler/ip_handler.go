package handler

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
	"github.com/gin-gonic/gin"
)

type ipLocator interface {
	Lookup(netip.Addr) (service.IPLocation, error)
}

type IPHandler struct {
	locator ipLocator
	trusted []netip.Prefix
}

func NewIPHandler(locator ipLocator, trustedProxies []string) (*IPHandler, error) {
	h := &IPHandler{locator: locator}
	for _, value := range trustedProxies {
		value = strings.TrimSpace(value)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			ip, ipErr := netip.ParseAddr(value)
			if ipErr != nil {
				return nil, fmt.Errorf("invalid ip.trusted-proxies entry %q", value)
			}
			ip = ip.Unmap()
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		h.trusted = append(h.trusted, prefix.Masked())
	}
	return h, nil
}

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

func (h *IPHandler) isTrusted(ip netip.Addr) bool {
	for _, prefix := range h.trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *IPHandler) clientIP(r *http.Request) netip.Addr {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	peer, err := netip.ParseAddr(remote)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	if !h.isTrusted(peer) {
		return peer
	}
	// Walk from the closest proxy to the first untrusted hop. Never trust the
	// leftmost value blindly; the original client may have supplied it.
	if value := r.Header.Get("X-Forwarded-For"); value != "" {
		parts := strings.Split(value, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				return peer
			}
			ip = ip.Unmap()
			if i == 0 || !h.isTrusted(ip) {
				return ip
			}
		}
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return ip.Unmap()
	}
	return peer
}

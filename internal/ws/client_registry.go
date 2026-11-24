package ws

import "sync"

const (
	RoleUser  = "user"
	RoleAgent = "agent"
)

// ClientRegistry tracks signaling clients for multi-client demux with legacy
// fallback. See docs/ws/MULTI_CLIENT_SIGNALING.md.
type ClientRegistry struct {
	mu           sync.RWMutex
	legacy       map[string]*ClientConn            // deviceID → last client (1:1 overwrite)
	byClientID   map[string]*ClientConn            // client_id → conn
	byDeviceRole map[string]map[string]*ClientConn // deviceID → role → conn
}

func newClientRegistry() *ClientRegistry {
	return &ClientRegistry{
		legacy:       map[string]*ClientConn{},
		byClientID:   map[string]*ClientConn{},
		byDeviceRole: map[string]map[string]*ClientConn{},
	}
}

func (r *ClientRegistry) Snapshot() []*ClientConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	clients := make([]*ClientConn, 0, len(r.byClientID))
	for _, client := range r.byClientID {
		clients = append(clients, client)
	}
	return clients
}

// NormalizeRole returns user|agent; empty/unknown → user.
func NormalizeRole(role string) string {
	switch role {
	case RoleAgent:
		return RoleAgent
	default:
		return RoleUser
	}
}

// Add registers conn in the legacy slot and byClientID. If multiplex is true,
// also occupies the device role slot (same role replaces and returns the previous conn).
func (r *ClientRegistry) Add(conn *ClientConn, multiplex bool) (replaced *ClientConn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.legacy[conn.DeviceID] = conn
	if conn.ClientID != "" {
		r.byClientID[conn.ClientID] = conn
	}
	if !multiplex || conn.Role == "" {
		return nil
	}
	role := NormalizeRole(conn.Role)
	conn.Role = role
	slots := r.byDeviceRole[conn.DeviceID]
	if slots == nil {
		slots = map[string]*ClientConn{}
		r.byDeviceRole[conn.DeviceID] = slots
	}
	if prev := slots[role]; prev != nil && prev != conn {
		replaced = prev
		if prev.ClientID != "" && r.byClientID[prev.ClientID] == prev {
			delete(r.byClientID, prev.ClientID)
		}
		if r.legacy[conn.DeviceID] == prev {
			// legacy already points at conn above
		}
	}
	slots[role] = conn
	return replaced
}

// PromoteMultiplex moves an already-registered legacy client into a role slot
// (e.g. after the first offer declares clientType). Same-role replace returns
// the previous occupant.
func (r *ClientRegistry) PromoteMultiplex(conn *ClientConn, role string) (replaced *ClientConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	role = NormalizeRole(role)
	conn.Role = role
	conn.Multiplex = true
	slots := r.byDeviceRole[conn.DeviceID]
	if slots == nil {
		slots = map[string]*ClientConn{}
		r.byDeviceRole[conn.DeviceID] = slots
	}
	if prev := slots[role]; prev != nil && prev != conn {
		replaced = prev
		if prev.ClientID != "" && r.byClientID[prev.ClientID] == prev {
			delete(r.byClientID, prev.ClientID)
		}
	}
	slots[role] = conn
	if conn.ClientID != "" {
		r.byClientID[conn.ClientID] = conn
	}
	r.legacy[conn.DeviceID] = conn
	return replaced
}

// Remove drops conn from all indexes (self-checked).
func (r *ClientRegistry) Remove(conn *ClientConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.legacy[conn.DeviceID] == conn {
		delete(r.legacy, conn.DeviceID)
	}
	if conn.ClientID != "" && r.byClientID[conn.ClientID] == conn {
		delete(r.byClientID, conn.ClientID)
	}
	if slots := r.byDeviceRole[conn.DeviceID]; slots != nil {
		role := NormalizeRole(conn.Role)
		if slots[role] == conn {
			delete(slots, role)
		}
		if len(slots) == 0 {
			delete(r.byDeviceRole, conn.DeviceID)
		}
	}
}

// ByClientID looks up a multiplex/legacy-registered connection by minted id.
func (r *ClientRegistry) ByClientID(clientID string) *ClientConn {
	if clientID == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byClientID[clientID]
}

// Legacy returns the last-registered client for a device (overwrite semantics).
func (r *ClientRegistry) Legacy(deviceID string) *ClientConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.legacy[deviceID]
}

// HasClient reports whether any client is registered for the device (legacy slot).
func (r *ClientRegistry) HasClient(deviceID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.legacy[deviceID]
	return ok
}

// ResolveDelivery picks the demux target: byClientID hit, else legacy.
func (r *ClientRegistry) ResolveDelivery(deviceID, clientID string) *ClientConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if clientID != "" {
		if c := r.byClientID[clientID]; c != nil {
			return c
		}
	}
	return r.legacy[deviceID]
}

package auth

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"arkkvm.com/arkkvm-cloud/internal/model"
)

// McpTokenStore is the persistence surface for MCP tokens (implemented by
// repository.McpTokenRepo), kept narrow so the service is mockable.
type McpTokenStore interface {
	Create(t *model.McpToken) error
	FindActiveByHash(hash string) (*model.McpToken, error)
	TouchLastUsed(id int64, now time.Time) error
	Revoke(id int64, now time.Time) error
}

// McpTokenService issues and resolves the dedicated arkkvm_mcp credential
// (doc 16 §2): long-lived, explicitly revocable, stored as SHA-256 only.
// Deliberately NOT a Login() session — it occupies no single-session slot,
// so MCP and browser sessions coexist without evicting each other.
// MCP credentials expire after inactivity, with an absolute reauthorization cap.
const McpTokenIdleTTL = 7 * 24 * time.Hour
const McpTokenMaxTTL = 30 * 24 * time.Hour

type McpTokenService struct {
	store     McpTokenStore
	OnRevoked func(string)
}

func NewMcpTokenService(store McpTokenStore) *McpTokenService {
	return &McpTokenService{store: store}
}

// Issue creates a token row and returns the plaintext exactly once — only
// its SHA-256 is persisted.
func (s *McpTokenService) Issue(ctx context.Context, userID int64) (string, error) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	token := "mcp2_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	row := &model.McpToken{
		UserID:    userID,
		TokenHash: hex.EncodeToString(sum[:]),
		Name:      "mcp",
		CreatedAt: time.Now(),
	}
	if err := s.store.Create(row); err != nil {
		return "", err
	}
	return token, nil
}

// Resolve maps a bearer token to its userID, or ErrInvalidToken. Touches
// last_used_at at most once per minute (a conditional UPDATE, no read-back).
func (s *McpTokenService) Resolve(ctx context.Context, token string) (int64, error) {
	if !strings.HasPrefix(token, "mcp2_") || len(token) != 69 {
		return 0, ErrInvalidToken
	}
	sum := sha256.Sum256([]byte(token))
	t, err := s.store.FindActiveByHash(hex.EncodeToString(sum[:]))
	if err != nil {
		return 0, ErrInvalidToken
	}
	now := time.Now()
	lastUsed := t.CreatedAt
	if t.LastUsedAt != nil && t.LastUsedAt.After(lastUsed) {
		lastUsed = *t.LastUsedAt
	}
	if t.CreatedAt.IsZero() || !now.Before(t.CreatedAt.Add(McpTokenMaxTTL)) || !now.Before(lastUsed.Add(McpTokenIdleTTL)) {
		return 0, ErrInvalidToken
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= time.Minute {
		_ = s.store.TouchLastUsed(t.ID, now)
	}
	return t.UserID, nil
}

// Revoke marks the token behind the presented bearer revoked. Idempotent:
// unknown or already-revoked tokens report success.
func (s *McpTokenService) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	t, err := s.store.FindActiveByHash(hex.EncodeToString(sum[:]))
	if errors.Is(err, model.ErrMcpTokenNotFound) || errors.Is(err, ErrInvalidToken) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.store.Revoke(t.ID, time.Now()); err != nil {
		return err
	}
	if s.OnRevoked != nil {
		s.OnRevoked(token)
	}
	return nil
}

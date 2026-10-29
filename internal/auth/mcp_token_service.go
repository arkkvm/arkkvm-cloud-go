package auth

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/arkkvm/arkkvm-cloud-go/internal/model"
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
//: long-lived, explicitly revocable, stored as SHA-256 only.
// Deliberately NOT a Login session — it occupies no single-session slot,
// so MCP and browser sessions coexist without evicting each other.
type McpTokenService struct {
	store McpTokenStore
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
	token := hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	row := &model.McpToken{
		UserID:    userID,
		TokenHash: hex.EncodeToString(sum[:]),
		Name:      "mcp",
	}
	if err := s.store.Create(row); err != nil {
		return "", err
	}
	return token, nil
}

// Resolve maps a bearer token to its userID, or ErrInvalidToken. Touches
// last_used_at at most once per minute (a conditional UPDATE, no read-back).
func (s *McpTokenService) Resolve(ctx context.Context, token string) (int64, error) {
	if token == "" {
		return 0, ErrInvalidToken
	}
	sum := sha256.Sum256([]byte(token))
	t, err := s.store.FindActiveByHash(hex.EncodeToString(sum[:]))
	if err != nil {
		return 0, ErrInvalidToken
	}
	now := time.Now()
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
	if err != nil {
		return nil
	}
	return s.store.Revoke(t.ID, time.Now())
}

package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestConfirmedPairingAccountSwitchAndRetry(t *testing.T) {
	s := newTestTokenService(t)
	ctx := context.Background()
	a, err := s.IssueConfirmedPairingToken(ctx, 41, "dev-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	pa, err := s.ExchangeConfirmedPairingToken(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if pa.Attempted {
		t.Fatal("first exchange was already marked attempted")
	}
	oldSecret := "previous-device-secret"
	b, err := s.IssueConfirmedPairingToken(ctx, 42, "dev-1", &oldSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeConfirmedPairingToken(ctx, a); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("previous account's token still works: %v", err)
	}
	pb, err := s.ExchangeConfirmedPairingToken(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if pb.UserID != 42 || pb.DeviceID != "dev-1" || pb.SecretToken == pa.SecretToken || pb.PreviousSecret == nil || *pb.PreviousSecret != oldSecret {
		t.Fatalf("wrong selected account or snapshot: %+v", pb)
	}
	retry, err := s.ExchangeConfirmedPairingToken(ctx, b)
	if err != nil || retry.SecretToken != pb.SecretToken || !retry.Attempted {
		t.Fatalf("exchange retry changed the credential: %v", err)
	}
	if _, _, err := s.Resolve(ctx, b); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("confirmation token must not be a login session")
	}
	// A confirmation for a different device must not invalidate this one.
	if _, err := s.IssueConfirmedPairingToken(ctx, 42, "dev-2", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeConfirmedPairingToken(ctx, b); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmedPairingRejectsUnconfirmedTokens(t *testing.T) {
	s := newTestTokenService(t)
	ctx := context.Background()
	oauth, err := s.IssuePairingToken(ctx, 42, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := s.Login(ctx, 42, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "invalid", oauth, legacy} {
		if _, err := s.ExchangeConfirmedPairingToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("unconfirmed token accepted: %v", err)
		}
	}
}

func TestConfirmedPairingExpiryIsNotExtendedByRetry(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	s := NewTokenService(rdb, "test-secret")
	ctx := context.Background()
	token, err := s.IssueConfirmedPairingToken(ctx, 42, "dev-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	mr.FastForward(pairingTokenTTL - time.Second)
	if _, err := s.ExchangeConfirmedPairingToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(2 * time.Second)
	if _, err := s.ExchangeConfirmedPairingToken(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired token still works: %v", err)
	}
}

func TestConcurrentConfirmationsLeaveOnlyLatestToken(t *testing.T) {
	s := newTestTokenService(t)
	ctx := context.Background()
	const count = 12
	tokens := make(chan string, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(userID int64) {
			defer wg.Done()
			token, err := s.IssueConfirmedPairingToken(ctx, userID, "dev-1", nil)
			if err != nil {
				t.Error(err)
				return
			}
			tokens <- token
		}(int64(i + 1))
	}
	wg.Wait()
	close(tokens)
	valid := 0
	for token := range tokens {
		if _, err := s.ExchangeConfirmedPairingToken(ctx, token); err == nil {
			valid++
		} else if !errors.Is(err, ErrInvalidToken) {
			t.Fatal(err)
		}
	}
	if valid != 1 {
		t.Fatalf("valid confirmation count = %d, want 1", valid)
	}
}

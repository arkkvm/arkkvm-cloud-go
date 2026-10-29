package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/arkkvm/arkkvm-cloud-go/internal/auth"
	"github.com/arkkvm/arkkvm-cloud-go/internal/repository"
	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
)

type pairingHarness struct {
	router *gin.Engine
	tokens *auth.TokenService
	mock   sqlmock.Sqlmock
	rdb    *redis.Client
}

func newPairingHarness(t *testing.T) *pairingHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: sqlDB, SkipInitializeWithVersion: true}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	tokens := auth.NewTokenService(rdb, "test-secret")
	handler := NewDeviceHandler(service.NewDeviceService(repository.NewDeviceRepo(db), nil), tokens)
	r := gin.New()
	r.POST("/devices/:id/bind", auth.RequireAuth(tokens), handler.Bind)
	r.POST("/devices/token", handler.ExchangeToken)
	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Error(err)
		}
	})
	return &pairingHarness{router: r, tokens: tokens, mock: mock, rdb: rdb}
}

func (h *pairingHarness) request(t *testing.T, path, credential, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

func pairingJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPairingSwitchAccountBeforeDeviceRegistration(t *testing.T) {
	h := newPairingHarness(t)
	ctx := context.Background()
	// OAuth returns a non-confirmed token. It must never claim even an existing device.
	oauthToken, err := h.tokens.IssuePairingToken(ctx, 41, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{oauthToken, "invalid"} {
		w := h.request(t, "/devices/token", "", `{"tempToken":"`+token+`"}`)
		if pairingJSON(t, w)["success"] != false {
			t.Fatalf("unconfirmed exchange succeeded: %s", w.Body.String())
		}
	}
	var first string
	var final *auth.DevicePairing
	for _, uid := range []int64{41, 42} {
		login, err := h.tokens.Login(ctx, uid, "")
		if err != nil {
			t.Fatal(err)
		}
		// Confirmation is allowed only a read, never INSERT/UPDATE.
		h.mock.ExpectQuery("SELECT .*device").WithArgs("dev-1", 1).WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "secret_token"}))
		w := h.request(t, "/devices/dev-1/bind", login, `{"userId":99}`)
		body := pairingJSON(t, w)
		if body["success"] != true {
			t.Fatalf("confirmation failed: %s", w.Body.String())
		}
		token := body["data"].(map[string]any)["tempToken"].(string)
		if uid == 41 {
			first = token
			continue
		}
		raw, err := h.rdb.Get(ctx, "ARK:AUTH:CONFIRMEDPAIR:"+token).Result()
		if err != nil {
			t.Fatal(err)
		}
		final = &auth.DevicePairing{}
		if err := json.Unmarshal([]byte(raw), final); err != nil {
			t.Fatal(err)
		}
		if final.UserID != 42 {
			t.Fatal("frontend-supplied userId overrode current login")
		}
	}
	// Switching accounts invalidates A's pending confirmation, without any DB writes.
	w := h.request(t, "/devices/token", "", `{"tempToken":"`+first+`"}`)
	if pairingJSON(t, w)["success"] != false {
		t.Fatal("old account token accepted")
	}
	// The device's existing /cloud/register still sends the exact same request
	// to /devices/token. It receives the same bare secretToken/userId response.
	for attempt := 0; attempt < 2; attempt++ {
		h.mock.ExpectBegin()
		if attempt == 0 {
			h.mock.ExpectExec("INSERT INTO .*ON DUPLICATE KEY UPDATE `id`=`id`").
				WithArgs("dev-1", int64(42), nil, nil, final.SecretToken, nil, nil).WillReturnResult(sqlmock.NewResult(0, 1))
		}
		h.mock.ExpectQuery("SELECT .*FOR UPDATE").WithArgs("dev-1", 1).
			WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "secret_token"}).AddRow("dev-1", 42, final.SecretToken))
		h.mock.ExpectCommit()
		w := h.request(t, "/devices/token", "", `{"tempToken":"`+final.TempToken+`"}`)
		body := pairingJSON(t, w)
		if w.Code != 200 || body["secretToken"] != final.SecretToken || body["userId"] != float64(42) || len(body) != 2 {
			t.Fatalf("device exchange contract changed: %s", w.Body.String())
		}
	}
}

func TestPairingConfirmationGuards(t *testing.T) {
	for _, tc := range []struct {
		name, credential, id string
		owner                int64
		dbError              bool
		success              bool
	}{
		{"new_device", "session", "dev-1", 0, false, true},
		{"same_owner", "session", "dev-1", 42, false, true},
		{"other_owner", "session", "dev-1", 99, false, false},
		{"database_error", "session", "dev-1", 0, true, false},
		{"missing_login", "", "dev-1", 0, false, false},
		{"pairing_not_session", "pairing", "dev-1", 0, false, false},
		{"oversized_device_id", "session", strings.Repeat("d", 33), 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPairingHarness(t)
			var credential string
			var err error
			if tc.credential == "session" {
				credential, err = h.tokens.Login(context.Background(), 42, "")
			}
			if tc.credential == "pairing" {
				credential, err = h.tokens.IssueConfirmedPairingToken(context.Background(), 42, tc.id, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.credential == "session" && len(tc.id) <= 32 {
				query := h.mock.ExpectQuery("SELECT .*device").WithArgs(tc.id, 1)
				if tc.dbError {
					query.WillReturnError(errors.New("database down"))
				} else {
					rows := sqlmock.NewRows([]string{"id", "user_id", "secret_token"})
					if tc.owner != 0 {
						rows.AddRow(tc.id, tc.owner, "existing-secret")
					}
					query.WillReturnRows(rows)
				}
			}
			if tc.name == "other_owner" {
				h.mock.ExpectQuery("SELECT .*user_identities").WithArgs(int64(99)).
					WillReturnRows(sqlmock.NewRows([]string{"provider", "email", "display_name"}).
						AddRow("apple", "owner@example.com", "Owner Name"))
			}
			w := h.request(t, "/devices/"+tc.id+"/bind", credential, "")
			body := pairingJSON(t, w)
			if body["success"] != tc.success {
				t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
			}
			if tc.credential != "session" && w.Code != 401 {
				t.Fatalf("wanted 401, got %d", w.Code)
			}
			if tc.name == "other_owner" {
				data := body["data"].(map[string]any)
				account := data["boundAccount"].(map[string]any)
				if data["reason"] != "DEVICE_ALREADY_BOUND" || data["action"] != "SIGN_IN_AS_BOUND_ACCOUNT_AND_UNBIND" || account["provider"] != "apple" || account["maskedEmail"] != "o***@example.com" || account["maskedDisplayName"] != "O***" {
					t.Fatalf("missing conflict hint: %s", w.Body.String())
				}
				for _, secret := range []string{"owner@example.com", "Owner Name", "existing-secret", "tempToken", "providerUserId"} {
					if strings.Contains(w.Body.String(), secret) {
						t.Fatalf("conflict leaked private data: %s", secret)
					}
				}
			}
		})
	}
}

func TestPairingConflictDoesNotDependOnOwnerProfileLookup(t *testing.T) {
	h := newPairingHarness(t)
	login, err := h.tokens.Login(context.Background(), 42, "")
	if err != nil {
		t.Fatal(err)
	}
	h.mock.ExpectQuery("SELECT .*device").WithArgs("dev-1", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id"}).AddRow("dev-1", 99))
	h.mock.ExpectQuery("SELECT .*user_identities").WithArgs(int64(99)).WillReturnError(errors.New("profile unavailable"))
	w := h.request(t, "/devices/dev-1/bind", login, "")
	body := pairingJSON(t, w)
	data := body["data"].(map[string]any)
	if body["success"] != false || data["reason"] != "DEVICE_ALREADY_BOUND" || data["boundAccount"] != nil {
		t.Fatalf("ownership guard changed: %s", w.Body.String())
	}
}

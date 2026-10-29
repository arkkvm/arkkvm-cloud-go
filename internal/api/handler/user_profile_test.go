package handler

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/arkkvm/arkkvm-cloud-go/internal/repository"
	"github.com/arkkvm/arkkvm-cloud-go/internal/service"
)

func TestMeReturnsIdentityProfileWhenUserFieldsAreMissing(t *testing.T) {
	for _, stored := range []any{nil, "", " \t"} {
		t.Run(fmt.Sprint(stored), func(t *testing.T) {
			sqlDB, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer sqlDB.Close()
			db, err := gorm.Open(mysql.New(mysql.Config{Conn: sqlDB, SkipInitializeWithVersion: true}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectQuery("SELECT .*user.*").WithArgs(int64(7), 1).
				WillReturnRows(sqlmock.NewRows([]string{"id", "email", "picture"}).AddRow(7, stored, nil))
			mock.ExpectQuery("SELECT .*user_identities.*").WithArgs(int64(7)).
				WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "provider", "display_name", "email", "avatar_url"}).AddRow(1, 7, "github", "User Name", "user@example.com", "https://img.test/avatar.png"))
			h := NewUserHandler(service.NewUserService(repository.NewUserRepo(db), repository.NewIdentityRepo(db)), nil)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/me", nil)
			c.Set("auth.userID", int64(7))
			h.Me(c)
			var body struct {
				Success bool     `json:"success"`
				Data    userView `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			v := body.Data
			if v.Provider == nil || *v.Provider != "github" {
				t.Fatalf("top-level provider missing: %s", w.Body.String())
			}
			if !body.Success || v.DisplayName == nil || *v.DisplayName != "User Name" || v.Email == nil || *v.Email != "user@example.com" || v.Picture == nil || *v.Picture != "https://img.test/avatar.png" {
				t.Fatalf("profile not exposed: %s", w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

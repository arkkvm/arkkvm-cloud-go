package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestCompleteBindingTransaction(t *testing.T) {
	old, fresh, newer := "old-secret", "candidate-secret", "newer-secret"
	for _, dialect := range []string{"mysql", "postgres"} {
		for _, tc := range []struct {
			name                        string
			owner                       int64
			stored, previous            *string
			update, success, failUpdate bool
		}{
			{"first_claim", 42, &fresh, nil, false, true, false},
			{"same_owner_repair", 42, &old, &old, true, true, false},
			{"lost_response_retry", 42, &fresh, &old, false, true, false},
			{"other_account_won_race", 99, &newer, nil, false, false, false},
			{"stale_retry_cannot_restore_old_credential", 42, &newer, &old, false, false, false},
			{"update_failure_rolls_back", 42, &old, &old, true, false, true},
		} {
			t.Run(dialect+"/"+tc.name, func(t *testing.T) {
				sqlDB, mock, err := sqlmock.New()
				if err != nil {
					t.Fatal(err)
				}
				defer sqlDB.Close()
				var driver gorm.Dialector = mysql.New(mysql.Config{Conn: sqlDB, SkipInitializeWithVersion: true})
				insert := "INSERT INTO .*device.*ON DUPLICATE KEY UPDATE `id`=`id`"
				if dialect == "postgres" {
					driver = postgres.New(postgres.Config{Conn: sqlDB})
					insert = `INSERT INTO .*device.*ON CONFLICT \("id"\) DO NOTHING`
				}
				db, err := gorm.Open(driver, &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
				if err != nil {
					t.Fatal(err)
				}
				mock.ExpectBegin()
				mock.ExpectExec(insert).WithArgs("dev-1", int64(42), nil, nil, fresh, nil, nil).WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectQuery("SELECT .*device.*FOR UPDATE").WithArgs("dev-1", 1).
					WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "secret_token"}).AddRow("dev-1", tc.owner, tc.stored))
				if tc.update {
					update := mock.ExpectExec("UPDATE .*device.*SET .*secret_token.*WHERE .*id.*user_id").WithArgs(fresh, "dev-1", int64(42))
					if tc.failUpdate {
						update.WillReturnError(errors.New("write failed"))
					} else {
						update.WillReturnResult(sqlmock.NewResult(0, 1))
					}
				}
				if tc.failUpdate {
					mock.ExpectRollback()
				} else {
					mock.ExpectCommit()
				}
				ok, err := NewDeviceRepo(db).CompleteBinding(context.Background(), "dev-1", 42, fresh, tc.previous, true)
				if ok != tc.success || (err != nil) != tc.failUpdate {
					t.Fatalf("ok=%v err=%v", ok, err)
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCompleteBindingInsertFailureDoesNotLeaveBinding(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: sqlDB, SkipInitializeWithVersion: true}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO").WillReturnError(errors.New("database unavailable"))
	mock.ExpectRollback()
	if ok, err := NewDeviceRepo(db).CompleteBinding(context.Background(), "dev-1", 42, "candidate", nil, true); ok || err == nil {
		t.Fatal("insert failure reported success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteBindingRetryCannotRecreateUnboundDevice(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: sqlDB, SkipInitializeWithVersion: true}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	// No INSERT may be issued on a retry. A previously removed row stays absent.
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .*FOR UPDATE").WithArgs("dev-1", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "secret_token"}))
	mock.ExpectRollback()
	if ok, err := NewDeviceRepo(db).CompleteBinding(context.Background(), "dev-1", 42, "candidate", nil, false); ok || !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("retry recreated an unbound device: %v %v", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

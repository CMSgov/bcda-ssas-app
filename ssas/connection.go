package ssas

import (
	"database/sql"
	"os"
	"time"

	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func CreateDB() (*gorm.DB, error) {
	databaseURL := os.Getenv("DATABASE_URL")

	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	// TODO: Allow connection settings to be configured by env vars
	// https://jira.cms.gov/browse/BCDA-7109
	sqlDB.SetMaxOpenConns(60)
	sqlDB.SetMaxIdleConns(40)
	sqlDB.SetConnMaxLifetime(time.Duration(5) * time.Minute)
	sqlDB.SetConnMaxIdleTime(time.Duration(30) * time.Second)

	db, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqlDB,
	}), &gorm.Config{})

	if err != nil {
		return nil, err
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

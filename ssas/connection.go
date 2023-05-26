package ssas

import (
	"database/sql"
	"os"
	"time"

	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Connection *gorm.DB

func init() {
	var err error
	Connection, err = createDB()

	if err != nil {
		Logger.Fatalf("Failed to create db %s", err.Error())
	}
}

func createDB() (*gorm.DB, error) {
	databaseURL := os.Getenv("DATABASE_URL")

	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	// db.SetMaxOpenConns(cfg.MaxOpenConns)
	// db.SetMaxIdleConns(cfg.MaxIdleConns)
	// db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMin) * time.Minute)

	sqlDB.SetMaxOpenConns(40)
	sqlDB.SetMaxIdleConns(40)
	sqlDB.SetConnMaxLifetime(time.Duration(5) * time.Minute)

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

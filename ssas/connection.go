package ssas

import (
	"database/sql"
	"os"
	"runtime"
	"time"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Variable substitution to support testing.
var LogFatal = log.Fatal

var Connection *gorm.DB

func init() {
	var err error
	Connection, err = createDB()

	if err != nil {
		logrus.Fatalf("Failed to create db %s", err.Error())
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

func Close(db *gorm.DB) {
	d, err := db.DB()
	if err != nil {
		log.Warnf("failed to retrieve db connection %v", err)
		return
	}
	if err := d.Close(); err != nil {
		_, file, line, _ := runtime.Caller(1)
		Logger.Infof("failed to close db connection at %s#%d because %s", file, line, err)
	}
}

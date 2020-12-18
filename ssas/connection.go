package ssas

import (
	"database/sql"
	"os"
	"runtime"
	"sync"
	"time"

	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Variable substitution to support testing.
var LogFatal = log.Fatal

var (
	once sync.Once
	db1  *gorm.DB
)

func GetDbConnection() *sql.DB {
	databaseURL := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		LogFatal(err)
	}
	pingErr := db.Ping()
	if pingErr != nil {
		LogFatal(pingErr)
	}
	return db
}

func GetGORMDbConnection() *gorm.DB {
	databaseURL := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
	if err != nil {
		LogFatal(err)
	}
	return db
}

func GetGORMDbConnection1() *gorm.DB {
	once.Do(func() {
		databaseURL := os.Getenv("DATABASE_URL")
		db, err := gorm.Open(postgres.Open(databaseURL), &gorm.Config{
			Logger:      logger.Default.LogMode(logger.Info),
			PrepareStmt: true,
		})
		if err != nil {
			LogFatal(err)
		}
		dbc, err := db.DB()
		if err != nil {
			log.Fatalf("Failed to retrieve database connection. Err: %v", err)
		}
		dbc.SetMaxOpenConns(25)
		dbc.SetMaxIdleConns(25)
		dbc.SetConnMaxLifetime(5 * time.Minute)
		db1 = db
	})
	return db1
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

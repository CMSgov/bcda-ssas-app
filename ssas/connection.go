package ssas

import (
	"database/sql"
	"os"
	"runtime"

	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Variable substitution to support testing.
var LogFatal = log.Fatal

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

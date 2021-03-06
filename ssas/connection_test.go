package ssas

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type ConnectionTestSuite struct {
	suite.Suite
	db     *sql.DB
	gormdb *gorm.DB
}

func (suite *ConnectionTestSuite) TestDbConnections() {

	// after this test, replace the original log.Fatal() function
	origLogFatal := LogFatal
	defer func() { LogFatal = origLogFatal }()

	// create the mock version of log.Fatal()
	LogFatal = func(args ...interface{}) {
		fmt.Println("FATAL (NO-OP)")
	}

	// get the real database URL
	actualDatabaseURL := os.Getenv("DATABASE_URL")

	// set the database URL to a bogus value to test negative scenarios
	os.Setenv("DATABASE_URL", "fake_db_url")

	// attempt to open DB connection with the bogus DB string
	suite.db = GetDbConnection()
	suite.gormdb = GetGORMDbConnection()

	// assert that Ping returns an error
	assert.Error(suite.T(), suite.db.Ping(), "Database should fail to connect (negative scenario)")
	db, err := suite.gormdb.DB()
	assert.NoError(suite.T(), err)
	assert.Error(suite.T(), db.Ping(), "Gorm database should fail to connect (negative scenario)")

	// close DBs to reset the test
	_ = suite.db.Close()
	Close(suite.gormdb)

	// set the database URL back to the real value to test the positive scenarios
	os.Setenv("DATABASE_URL", actualDatabaseURL)

	suite.db = GetDbConnection()
	defer suite.db.Close()

	suite.gormdb = GetGORMDbConnection()
	defer Close(suite.gormdb)

	// assert that Ping() does not return an error
	assert.Nil(suite.T(), suite.db.Ping(), "Error connecting to sql database")
	db, err = suite.gormdb.DB()
	assert.NoError(suite.T(), err)
	assert.NoError(suite.T(), db.Ping(), "Error connecting to gorm database")
}

func TestConnectionTestSuite(t *testing.T) {
	suite.Run(t, new(ConnectionTestSuite))
}

package ssas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ConnectionTestSuite struct {
	suite.Suite
}

func (suite *ConnectionTestSuite) TestDbConnections() {
	db, err := Connection.DB()
	assert.NoError(suite.T(), err)
	assert.NoError(suite.T(), db.Ping(), "Error connecting to gorm database")
}

func TestConnectionTestSuite(t *testing.T) {
	suite.Run(t, new(ConnectionTestSuite))
}

package ssas

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type ConnectionTestSuite struct {
	suite.Suite
}

func TestConnectionTestSuite(t *testing.T) {
	suite.Run(t, new(ConnectionTestSuite))
}

func (s *ConnectionTestSuite) TestDbConnections() {
	db, err := CreateDB()
	require.NoError(s.T(), err)
	conn, err := db.DB()
	assert.NoError(s.T(), err)
	assert.NoError(s.T(), conn.Ping(), "Error connecting to gorm database")
	err = conn.Close()
	require.NoError(s.T(), err)

}

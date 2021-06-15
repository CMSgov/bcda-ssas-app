package ssas

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gopkg.in/macaroon.v2"
	"gorm.io/gorm"
	"testing"
	"time"
)

type RootKeyTestSuite struct {
	suite.Suite
	db *gorm.DB
}

func (s *RootKeyTestSuite) SetupSuite() {
	s.db = GetGORMDbConnection()
}

func (s *RootKeyTestSuite) TearDownSuite() {
	Close(s.db)
}

func TestRootKeyTestSuite(t *testing.T) {
	suite.Run(t, new(RootKeyTestSuite))
}

func (s *RootKeyTestSuite) TestRootKeyMacaroonGeneration() {
	expiration := time.Duration(5*24) * time.Hour
	rk, _ := NewRootKey(expiration)
	m, _ := rk.Generate([]Caveats{map[string]string{"foo": "bar"}}, "my-location")

	var um macaroon.Macaroon
	b, _ := base64.StdEncoding.DecodeString(m)
	_ = um.UnmarshalBinary(b)

	err := um.Verify([]byte(rk.Key), func(caveat string) error {
		return nil
	}, nil)
	assert.NoError(s.T(), err)
}

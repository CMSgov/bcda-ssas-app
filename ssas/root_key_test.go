package ssas

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gopkg.in/macaroon.v2"
	"gorm.io/gorm"
)

type RootKeyTestSuite struct {
	suite.Suite
	db *gorm.DB
	r  *RootKeyRepository
}

func (s *RootKeyTestSuite) SetupTest() {
	var err error
	s.db, err = CreateDB()
	require.NoError(s.T(), err)
	s.r = NewRootKeyRepository(s.db)

}

func (s *RootKeyTestSuite) TearDownTest() {
	db, err := s.db.DB()
	require.NoError(s.T(), err)
	err = db.Close()
	require.NoError(s.T(), err)
}

func TestRootKeyTestSuite(t *testing.T) {
	suite.Run(t, new(RootKeyTestSuite))
}

func (s *RootKeyTestSuite) TestRootKeyMacaroonGeneration() {
	expiration := time.Duration(5*24) * time.Hour
	rk, _ := s.r.NewRootKey(context.Background(), 123, time.Now().Add(expiration))
	m, _ := rk.Generate([]Caveats{map[string]string{"foo": "bar"}}, "my-location")

	var um macaroon.Macaroon
	b, _ := base64.StdEncoding.DecodeString(m)
	_ = um.UnmarshalBinary(b)

	caveats, err := um.VerifySignature([]byte(rk.Key), nil)
	assert.Len(s.T(), caveats, 1)
	assert.Equal(s.T(), "foo=bar", caveats[0])
	assert.NoError(s.T(), err)
}

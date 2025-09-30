package ssas

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type CacheEntriesTestSuite struct {
	suite.Suite
	db *gorm.DB
	r  *DenylistEntryRepository
}

func (s *CacheEntriesTestSuite) SetupTest() {
	var err error
	s.db, err = CreateDB()
	require.NoError(s.T(), err)
	s.r = NewDenylistEntryRepository(s.db)

}

func (s *CacheEntriesTestSuite) TearDownTest() {
	db, err := s.db.DB()
	require.NoError(s.T(), err)
	err = db.Close()
	require.NoError(s.T(), err)
}

func (s *CacheEntriesTestSuite) TestGetUnexpiredCacheEntries() {
	entries, err := s.r.GetUnexpiredDenylistEntries(context.Background())
	require.Nil(s.T(), err)
	origEntries := len(entries)

	entryDate := time.Now().Add(time.Minute * -5).UnixNano()
	expiration := time.Now().Add(time.Minute * 5).UnixNano()
	e1 := DenylistEntry{Key: "key1", EntryDate: entryDate, CacheExpiration: expiration}
	e2 := DenylistEntry{Key: "key2", EntryDate: entryDate, CacheExpiration: expiration}

	if err = s.db.Save(&e1).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.db.Save(&e2).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	entries, err = s.r.GetUnexpiredDenylistEntries(context.Background())
	assert.Nil(s.T(), err)
	assert.True(s.T(), len(entries) == origEntries+2)

	err = s.db.Unscoped().Delete(&e1).Error
	assert.Nil(s.T(), err)
	err = s.db.Unscoped().Delete(&e2).Error
	assert.Nil(s.T(), err)
}

func (s *CacheEntriesTestSuite) TestCreateDenylistEntryEmptyKey() {
	entryDate := time.Now().Add(time.Minute * -5)
	expiration := time.Now().Add(time.Minute * 5)

	_, err := s.r.CreateDenylistEntry(context.Background(), "", entryDate, expiration)
	assert.NotNil(s.T(), err)

	e, err := s.r.CreateDenylistEntry(context.Background(), "another_key", entryDate, expiration)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), "another_key", e.Key)

	err = s.db.Unscoped().Delete(&e).Error
	assert.Nil(s.T(), err)
}

func TestCacheEntriesTestSuite(t *testing.T) {
	suite.Run(t, new(CacheEntriesTestSuite))
}

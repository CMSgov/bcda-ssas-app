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
}

func (s *CacheEntriesTestSuite) SetupSuite() {
	s.db = Connection
}

func (s *CacheEntriesTestSuite) TestGetUnexpiredCacheEntries() {
	entries, err := GetUnexpiredBlacklistEntries(context.Background())
	require.Nil(s.T(), err)
	origEntries := len(entries)

	entryDate := time.Now().Add(time.Minute * -5).UnixNano()
	expiration := time.Now().Add(time.Minute * 5).UnixNano()
	e1 := BlacklistEntry{Key: "key1", EntryDate: entryDate, CacheExpiration: expiration}
	e2 := BlacklistEntry{Key: "key2", EntryDate: entryDate, CacheExpiration: expiration}

	if err = s.db.Save(&e1).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.db.Save(&e2).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	entries, err = GetUnexpiredBlacklistEntries(context.Background())
	assert.Nil(s.T(), err)
	assert.True(s.T(), len(entries) == origEntries+2)

	err = s.db.Unscoped().Delete(&e1).Error
	assert.Nil(s.T(), err)
	err = s.db.Unscoped().Delete(&e2).Error
	assert.Nil(s.T(), err)
}

func (s *CacheEntriesTestSuite) TestCreateBlacklistEntryEmptyKey() {
	entryDate := time.Now().Add(time.Minute * -5)
	expiration := time.Now().Add(time.Minute * 5)

	_, err := CreateBlacklistEntry(context.Background(), "", entryDate, expiration)
	assert.NotNil(s.T(), err)

	e, err := CreateBlacklistEntry(context.Background(), "another_key", entryDate, expiration)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), "another_key", e.Key)

	err = s.db.Unscoped().Delete(&e).Error
	assert.Nil(s.T(), err)
}

func TestCacheEntriesTestSuite(t *testing.T) {
	suite.Run(t, new(CacheEntriesTestSuite))
}

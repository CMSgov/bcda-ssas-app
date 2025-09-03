package service

import (
	"context"
	"crypto/rand"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

// Using a constant for this makes the tests more readable; any arbitrary value longer than the test execution time
// should work
var (
	expiration     = 90 * time.Minute
	timeExpired    = time.Now().Add(time.Minute * -5)
	timeNotExpired = time.Now().Add(time.Minute * 5)
)

type TokenCacheTestSuite struct {
	suite.Suite
	t  *Denylist
	db *gorm.DB
}

var maxInt = big.NewInt(100)

func (s *TokenCacheTestSuite) SetupSuite() {
	s.db = ssas.Connection
	c := NewCacheConfig()
	s.t = NewDenylist(context.Background(), c)
}

func (s *TokenCacheTestSuite) TearDownTest() {
	s.t.c.Flush()
	err := s.db.Exec("DELETE FROM denylist_entries;").Error
	assert.Nil(s.T(), err)
}

func (s *TokenCacheTestSuite) TestLoadFromDatabaseEmpty() {
	key := "tokenID"

	var denyListEntries []ssas.DenylistEntry
	s.db.Unscoped().Find(&denyListEntries)
	assert.Len(s.T(), denyListEntries, 0)
	if err := s.t.LoadFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Len(s.T(), s.t.c.Items(), 0)

	if err := s.t.DenylistToken(context.Background(), key, expiration); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	s.db.Unscoped().Find(&denyListEntries)
	assert.Len(s.T(), denyListEntries, 1)
	if err := s.t.LoadFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Len(s.T(), s.t.c.Items(), 1)
	for _, item := range s.t.c.Items() {
		assert.True(s.T(), item.Expiration > 0, "Should have a positive expiration value")
	}
}

func (s *TokenCacheTestSuite) TestLoadFromDatabaseSomeExpired() {
	expiredKey := "expiredKey"
	notExpiredKey := "notExpiredKey"
	var err error
	entryDate := timeExpired.Unix()
	expired := timeExpired.UnixNano()
	notExpired := timeNotExpired.UnixNano()
	entryExpired := ssas.DenylistEntry{Key: expiredKey, EntryDate: entryDate, CacheExpiration: expired}
	entryDuplicateExpired := ssas.DenylistEntry{Key: notExpiredKey, EntryDate: entryDate, CacheExpiration: expired}
	entryNotExpired := ssas.DenylistEntry{Key: notExpiredKey, EntryDate: entryDate, CacheExpiration: notExpired}

	if err = s.db.Save(&entryExpired).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.db.Save(&entryDuplicateExpired).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	if err = s.t.LoadFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.Len(s.T(), s.t.c.Items(), 0)
	assert.False(s.T(), s.t.IsTokenDenylisted(expiredKey))
	// This result changes after putting a new entry in the database that has not expired.
	assert.False(s.T(), s.t.IsTokenDenylisted(notExpiredKey))

	if err = s.db.Save(&entryNotExpired).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.t.LoadFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.Len(s.T(), s.t.c.Items(), 1)
	assert.False(s.T(), s.t.IsTokenDenylisted(expiredKey))
	// The second time we check, this key is denylisted
	assert.True(s.T(), s.t.IsTokenDenylisted(notExpiredKey))
}

func (s *TokenCacheTestSuite) TestLoadFromDatabase() {
	var err error
	entryDate := timeExpired.Unix()
	expiration := timeNotExpired.UnixNano()
	e1 := ssas.DenylistEntry{Key: "key1", EntryDate: entryDate, CacheExpiration: expiration}
	e2 := ssas.DenylistEntry{Key: "key2", EntryDate: entryDate, CacheExpiration: expiration}

	if err = s.db.Save(&e1).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.db.Save(&e2).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	if err = s.t.LoadFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.Len(s.T(), s.t.c.Items(), 2)
	assert.True(s.T(), s.t.IsTokenDenylisted(e1.Key))
	assert.True(s.T(), s.t.IsTokenDenylisted(e2.Key))

	obj1, _, found := s.t.c.GetWithExpiration(e1.Key)
	assert.True(s.T(), found)
	insertedDate1, ok := obj1.(int64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), entryDate, insertedDate1)

	obj2, _, found := s.t.c.GetWithExpiration(e2.Key)
	assert.True(s.T(), found)
	insertedDate2, ok := obj2.(int64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), entryDate, insertedDate2)
}

func (s *TokenCacheTestSuite) TestIsTokenDenylistedTrue() {
	randInt, err := rand.Int(rand.Reader, maxInt)
	assert.Nil(s.T(), err)
	key := strconv.Itoa(int(randInt.Int64()))
	err = s.t.c.Add(key, "value does not matter", expiration)
	if err != nil {
		assert.FailNow(s.T(), "unable to set cache value: "+err.Error())
	}
	assert.True(s.T(), s.t.IsTokenDenylisted(key))
}

func (s *TokenCacheTestSuite) TestIsTokenDenylistedExpired() {
	minimalDuration := 1 * time.Nanosecond
	randInt, err := rand.Int(rand.Reader, maxInt)
	assert.Nil(s.T(), err)
	key := strconv.Itoa(int(randInt.Int64()))
	err = s.t.c.Add(key, "value does not matter", minimalDuration)
	if err != nil {
		assert.FailNow(s.T(), "unable to set cache value: "+err.Error())
	}
	time.Sleep(minimalDuration * 5)
	assert.False(s.T(), s.t.IsTokenDenylisted(key))
}

func (s *TokenCacheTestSuite) TestIsTokenDenylistedFalse() {
	randInt, err := rand.Int(rand.Reader, maxInt)
	assert.Nil(s.T(), err)
	key := strconv.Itoa(int(randInt.Int64()))
	assert.False(s.T(), s.t.IsTokenDenylisted(key))
}

func (s *TokenCacheTestSuite) TestDenylistToken() {
	randInt, err := rand.Int(rand.Reader, maxInt)
	assert.Nil(s.T(), err)
	key := strconv.Itoa(int(randInt.Int64()))
	if err := s.t.DenylistToken(context.Background(), key, expiration); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	_, found := s.t.c.Get(key)
	assert.True(s.T(), found)

	entries, err := ssas.GetUnexpiredDenylistEntries(context.Background())
	assert.Nil(s.T(), err)
	assert.Len(s.T(), entries, 1)
	assert.Equal(s.T(), key, entries[0].Key)
}

func (s *TokenCacheTestSuite) TestStartCacheRefreshTicker() {
	stopCacheRefreshTicker()

	var err error
	entryDate := timeExpired.Unix()
	expiration := timeNotExpired.UnixNano()
	key1 := "key1"
	key2 := "key2"

	e1 := ssas.DenylistEntry{Key: key1, EntryDate: entryDate, CacheExpiration: expiration}
	if err = s.db.Save(&e1).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.False(s.T(), s.t.IsTokenDenylisted(key1))
	assert.False(s.T(), s.t.IsTokenDenylisted(key2))

	ticker, cancelFunc := s.t.startCacheRefreshTicker(time.Millisecond * 250)
	defer func() {
		ticker.Stop()
		cancelFunc()
	}()

	time.Sleep(time.Millisecond * 350)
	assert.True(s.T(), s.t.IsTokenDenylisted(key1))
	assert.False(s.T(), s.t.IsTokenDenylisted(key2))

	e2 := ssas.DenylistEntry{Key: key2, EntryDate: entryDate, CacheExpiration: expiration}
	if err = s.db.Save(&e2).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	time.Sleep(time.Millisecond * 250)
	assert.True(s.T(), s.t.IsTokenDenylisted(key1))
	assert.True(s.T(), s.t.IsTokenDenylisted(key2))
}

func (s *TokenCacheTestSuite) TestDenylistTokenKeyExists() {
	randInt, err := rand.Int(rand.Reader, maxInt)
	assert.Nil(s.T(), err)
	key := strconv.Itoa(int(randInt.Int64()))

	// Place key in denylist
	if err := s.t.DenylistToken(context.Background(), key, expiration); err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	// Verify key exists in cache
	obj1, found := s.t.c.Get(key)
	assert.True(s.T(), found)

	// Verify key exists in database
	entries1, err := ssas.GetUnexpiredDenylistEntries(context.Background())
	assert.Nil(s.T(), err)
	assert.Len(s.T(), entries1, 1)
	assert.Equal(s.T(), key, entries1[0].Key)
	assert.Equal(s.T(), obj1, entries1[0].EntryDate)

	// The value stored is the current time expressed as in Unix time.
	// Wait to make sure the new denylist entry has a different value
	time.Sleep(2 * time.Second)

	// Place key in cache a second time; the expiration will be different
	if err := s.t.DenylistToken(context.Background(), key, expiration); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	// Verify retrieving key from cache gets new value (timestamp)
	obj2, found := s.t.c.Get(key)
	assert.True(s.T(), found)
	assert.NotEqual(s.T(), obj1, obj2)

	// Verify both keys are in the database, and that they are in time order
	entries2, err := ssas.GetUnexpiredDenylistEntries(context.Background())
	assert.Nil(s.T(), err)
	// 2 entries were added in this test; 1 was added in middleware_test
	// depending on which order the tests are completed, sometimes there are 2 entries and sometimes there are 3
	assert.Len(s.T(), entries2, 2)
	assert.Equal(s.T(), key, entries2[1].Key)
	assert.Equal(s.T(), obj2, entries2[1].EntryDate)

	// Verify that the denylisted object changed in both cache and database
	assert.NotEqual(s.T(), obj1, obj2)
	assert.NotEqual(s.T(), entries1[0].CacheExpiration, entries2[1].CacheExpiration)

	// Show that loading the cache from the database preserves the most recent entry, even if two
	//   objects with the same key are unexpired
	err = s.t.LoadFromDatabase()
	assert.Nil(s.T(), err)
	obj3, found := s.t.c.Get(key)
	assert.True(s.T(), found)
	assert.Equal(s.T(), obj2, obj3)
	assert.NotEqual(s.T(), obj1, obj3)
}

func TestTokenCacheTestSuite(t *testing.T) {
	suite.Run(t, new(TokenCacheTestSuite))
}

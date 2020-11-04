package blacklist

import (
	"encoding/json"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/jinzhu/gorm"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// Using a constant for this makes the tests more readable; any arbitrary value longer than the test execution time
// should work
var (
	expiration     = 90 * time.Minute
	timeExpired    = time.Now().Add(time.Minute * -5)
	timeNotExpired = time.Now().Add(time.Minute * 5)
)

type BlacklistTestSuite struct {
	suite.Suite
	b  *blacklist
	db *gorm.DB
}

func (s *BlacklistTestSuite) SetupSuite() {
	s.db = ssas.GetGORMDbConnection()
	s.b = newBlacklist(24*time.Hour,
		15*time.Minute, 15*time.Minute,
		24*time.Hour, 24*time.Hour,
		5*time.Minute, 5*time.Minute)
}

func (s *BlacklistTestSuite) TearDownSuite() {
	s.db.Close()
	s.b.close()
}

func (s *BlacklistTestSuite) TearDownTest() {
	s.b.tc.Flush()
	s.b.gc.Flush()

	err := s.db.Unscoped().Delete(&TokenEntry{}).Error
	assert.Nil(s.T(), err)
	err = s.db.Unscoped().Delete(&GroupEntry{}).Error
	assert.Nil(s.T(), err)
}

func (s *BlacklistTestSuite) TestLoadFromDatabaseEmpty() {
	key := "tokenID"

	var blackListEntries []TokenEntry
	s.db.Unscoped().Find(&blackListEntries)
	assert.Len(s.T(), blackListEntries, 0)
	if err := s.b.loadTokensFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Len(s.T(), s.b.tc.Items(), 0)

	if err := s.b.BlacklistToken(key); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	s.db.Unscoped().Find(&blackListEntries)
	assert.Len(s.T(), blackListEntries, 1)
	if err := s.b.loadTokensFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Len(s.T(), s.b.tc.Items(), 1)
}

func (s *BlacklistTestSuite) TestLoadFromDatabaseSomeExpired() {
	expiredKey := "expiredKey"
	notExpiredKey := "notExpiredKey"
	var err error
	entryDate := timeExpired.Unix()
	expired := timeExpired.UnixNano()
	notExpired := timeNotExpired.UnixNano()
	entryExpired := TokenEntry{Key: expiredKey, EntryDate: entryDate, CacheExpiration: expired}
	entryDuplicateExpired := TokenEntry{Key: notExpiredKey, EntryDate: entryDate, CacheExpiration: expired}
	entryNotExpired := TokenEntry{Key: notExpiredKey, EntryDate: entryDate, CacheExpiration: notExpired}

	if err = s.db.Save(&entryExpired).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.db.Save(&entryDuplicateExpired).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	if err = s.b.loadTokensFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.Len(s.T(), s.b.tc.Items(), 0)
	assert.False(s.T(), s.b.IsTokenBlacklisted(expiredKey))
	// This result changes after putting a new entry in the database that has not expired.
	assert.False(s.T(), s.b.IsTokenBlacklisted(notExpiredKey))

	if err = s.db.Save(&entryNotExpired).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.b.loadTokensFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.Len(s.T(), s.b.tc.Items(), 1)
	assert.False(s.T(), s.b.IsTokenBlacklisted(expiredKey))
	// The second time we check, this key is blacklisted
	assert.True(s.T(), s.b.IsTokenBlacklisted(notExpiredKey))
}

func (s *BlacklistTestSuite) TestLoadFromDatabase() {
	var err error
	entryDate := timeExpired.Unix()
	expiration := timeNotExpired.UnixNano()
	e1 := TokenEntry{Key: "key1", EntryDate: entryDate, CacheExpiration: expiration}
	e2 := TokenEntry{Key: "key2", EntryDate: entryDate, CacheExpiration: expiration}

	if err = s.db.Save(&e1).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	if err = s.db.Save(&e2).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	if err = s.b.loadTokensFromDatabase(); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.Len(s.T(), s.b.tc.Items(), 2)
	assert.True(s.T(), s.b.IsTokenBlacklisted(e1.Key))
	assert.True(s.T(), s.b.IsTokenBlacklisted(e2.Key))

	obj1, _, found := s.b.tc.GetWithExpiration(e1.Key)
	assert.True(s.T(), found)
	insertedDate1, ok := obj1.(int64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), entryDate, insertedDate1)

	obj2, _, found := s.b.tc.GetWithExpiration(e2.Key)
	assert.True(s.T(), found)
	insertedDate2, ok := obj2.(int64)
	assert.True(s.T(), ok)
	assert.Equal(s.T(), entryDate, insertedDate2)
}

func (s *BlacklistTestSuite) TestIsTokenBlacklistedTrue() {
	key := strconv.Itoa(rand.Int())
	err := s.b.tc.Add(key, "value does not matter", expiration)
	if err != nil {
		assert.FailNow(s.T(), "unable to set cache value: "+err.Error())
	}
	assert.True(s.T(), s.b.IsTokenBlacklisted(key))
}

func (s *BlacklistTestSuite) TestIsTokenBlacklistedExpired() {
	minimalDuration := 1 * time.Nanosecond
	key := strconv.Itoa(rand.Int())
	err := s.b.tc.Add(key, "value does not matter", minimalDuration)
	if err != nil {
		assert.FailNow(s.T(), "unable to set cache value: "+err.Error())
	}
	time.Sleep(minimalDuration * 5)
	assert.False(s.T(), s.b.IsTokenBlacklisted(key))
}

func (s *BlacklistTestSuite) TestIsTokenBlacklistedFalse() {
	key := strconv.Itoa(rand.Int())
	assert.False(s.T(), s.b.IsTokenBlacklisted(key))
}

func (s *BlacklistTestSuite) TestBlacklistToken() {
	key := strconv.Itoa(rand.Int())
	if err := s.b.BlacklistToken(key); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	_, found := s.b.tc.Get(key)
	assert.True(s.T(), found)

	entries, err := getUnexpiredTokenEntries()
	assert.Nil(s.T(), err)
	assert.Len(s.T(), entries, 1)
	assert.Equal(s.T(), key, entries[0].Key)
}

func (s *BlacklistTestSuite) TestCacheRefresherTicker() {
	entryDate := timeExpired.Unix()
	expiration := timeNotExpired.UnixNano()
	key1 := "key1"
	key2 := "key2"

	b := newBlacklist(24*time.Hour,
		15*time.Minute, 15*time.Minute,
		24*time.Hour, 24*time.Hour,
		250*time.Millisecond, 250*time.Millisecond)
	defer b.close()

	e1 := TokenEntry{Key: key1, EntryDate: entryDate, CacheExpiration: expiration}
	if err := s.db.Save(&e1).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	assert.False(s.T(), b.IsTokenBlacklisted(key1))
	assert.False(s.T(), b.IsTokenBlacklisted(key2))

	time.Sleep(time.Millisecond * 350)
	assert.True(s.T(), b.IsTokenBlacklisted(key1))
	assert.False(s.T(), b.IsTokenBlacklisted(key2))

	e2 := TokenEntry{Key: key2, EntryDate: entryDate, CacheExpiration: expiration}
	if err := s.db.Save(&e2).Error; err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	time.Sleep(time.Millisecond * 250)
	assert.True(s.T(), b.IsTokenBlacklisted(key1))
	assert.True(s.T(), b.IsTokenBlacklisted(key2))
}

func (s *BlacklistTestSuite) TestBlacklistTokenKeyExists() {
	key := strconv.Itoa(rand.Int())

	// Place key in blacklist
	if err := s.b.BlacklistToken(key); err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	// Verify key exists in cache
	obj1, found := s.b.tc.Get(key)
	assert.True(s.T(), found)

	// Verify key exists in database
	entries1, err := getUnexpiredTokenEntries()
	assert.Nil(s.T(), err)
	assert.Len(s.T(), entries1, 1)
	assert.Equal(s.T(), key, entries1[0].Key)
	assert.Equal(s.T(), obj1, entries1[0].EntryDate)

	// The value stored is the current time expressed as in Unix time.
	// Wait to make sure the new blacklist entry has a different value
	time.Sleep(2 * time.Second)

	// Place key in cache a second time; the expiration will be different
	if err := s.b.BlacklistToken(key); err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	// Verify retrieving key from cache gets new value (timestamp)
	obj2, found := s.b.tc.Get(key)
	assert.True(s.T(), found)
	assert.NotEqual(s.T(), obj1, obj2)

	// Verify both keys are in the database, and that they are in time order
	entries2, err := getUnexpiredTokenEntries()
	assert.Nil(s.T(), err)
	// 2 entries were added in this test; 1 was added in middleware_test
	// depending on which order the tests are completed, sometimes there are 2 entries and sometimes there are 3
	assert.Len(s.T(), entries2, 2)
	assert.Equal(s.T(), key, entries2[1].Key)
	assert.Equal(s.T(), obj2, entries2[1].EntryDate)

	// Verify that the blacklisted object changed in both cache and database
	assert.NotEqual(s.T(), obj1, obj2)
	assert.NotEqual(s.T(), entries1[0].CacheExpiration, entries2[1].CacheExpiration)

	// Show that loading the cache from the database preserves the most recent entry, even if two
	//   objects with the same key are unexpired
	err = s.b.loadTokensFromDatabase()
	assert.Nil(s.T(), err)
	obj3, found := s.b.tc.Get(key)
	assert.True(s.T(), found)
	assert.Equal(s.T(), obj2, obj3)
	assert.NotEqual(s.T(), obj1, obj3)
}

func (s *BlacklistTestSuite) TestGroupBlacklist() {
	expirationTime := time.Millisecond
	uuid := uuid.New() // use UUID to avoid deleting data that may not have been created by this test
	group := ssas.Group{XData: `{"cms_ids":["` + uuid + `"]}`}
	matchingEntry := groupEntry{GroupFieldXData, `{"cms_ids":"` + uuid + `"}`}
	nonMatchingEntry := groupEntry{GroupFieldXData, `{}`}
	invalidMatchEntry := groupEntry{GroupFieldXData, `{` + uuid}
	noExpire := newBlacklist(72*time.Hour,
		24*time.Minute, 1*time.Millisecond,
		24*time.Hour, 24*time.Hour, // Since we have a 24h expire, we shouldn't expect any entries to age out
		5*time.Minute, 1*time.Millisecond)
	immediateExpire := newBlacklist(24*time.Hour,
		5*time.Minute, 1*time.Millisecond,
		24*time.Hour, expirationTime, // Since we have a near zero expiration, we expect the entry to age out immediately.
		5*time.Minute, 1*time.Millisecond)
	cacheExpire := newBlacklist(24*time.Hour,
		5*time.Minute, 1*time.Millisecond,
		24*time.Hour, expirationTime, // Since we have a near zero expiration, we expect the entry to age out immediately.
		5*time.Minute, 5*time.Minute) // Set the ticker time to longer to rely on the cache expiration
	defer func() {
		noExpire.close()
		immediateExpire.close()
	}()

	tests := []struct {
		name           string
		blacklistEntry groupEntry
		b              *blacklist
		isBlacklisted  bool
	}{
		{"Matching db-expired", matchingEntry, immediateExpire, false},
		{"Matching cache-expired", matchingEntry, cacheExpire, false},
		{"Matching not expired", matchingEntry, noExpire, true},
		{"Not matching expired", nonMatchingEntry, immediateExpire, false},
		{"Not matching not expired", nonMatchingEntry, noExpire, false},
		{"Not matching invalid JSON on blacklist", invalidMatchEntry, noExpire, false},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			assert.NoError(t, tt.b.BlacklistGroup(tt.blacklistEntry.field, tt.blacklistEntry.expression))
			<-time.After(2 * expirationTime) // Wait sometime to ensure that expirations work
			assert.Equal(t, tt.isBlacklisted, tt.b.IsGroupBlacklisted(group))
			assert.NoError(t, s.db.Unscoped().Delete(&GroupEntry{}, "expression = ?", tt.blacklistEntry.expression).Error)
		})
	}

	assert.False(s.T(), noExpire.IsGroupBlacklisted(ssas.Group{XData: "INVALID_JSON"}))
}
func (s *BlacklistTestSuite) TestCheckXData() {
	// Need to erase any time information that we may have included in our test set
	convertMap := func(input map[string]interface{}) map[string]interface{} {
		res, err := json.Marshal(input)
		if err != nil {
			return nil
		}
		var output map[string]interface{}
		if err := json.Unmarshal(res, &output); err != nil {
			return nil
		}
		return output
	}

	var baseXData = convertMap(map[string]interface{}{
		"cms_ids":                []string{"A9994", "A9992", "A9990"},
		"someIntegerField":       123,
		"someFloatingPointField": 456.789,
		"someTrueBooleanField":   true,
		"someFalseBooleanField":  false,
		"someNestedField": map[string]interface{}{
			"nestedFieldArray": []int{1, 2, 3, 4},
			"nestedNestedField": map[string]interface{}{
				"someStringField": "foo",
			},
		},
	})

	tests := []struct {
		name       string
		expression map[string]interface{}
		hasMatch   bool
	}{
		{"Has match on integer field",
			map[string]interface{}{"nonMatchingField": "0", "someIntegerField": ""},
			true},
		{"Does not match on integer field",
			map[string]interface{}{"nonMatchingField": "0", "someIntegerField": "12[4|5]"},
			false},
		{"Has match on floating point field",
			map[string]interface{}{"nonMatchingField": "0", "someFloatingPointField": "456.78[9|0]"},
			true},
		{"Does not match on floating point field",
			map[string]interface{}{"nonMatchingField": "0", "someFloatingPointField": "456.78$"},
			false},
		{"Has match on boolean field",
			map[string]interface{}{"nonMatchingField": "0", "someTrueBooleanField": "true"},
			true},
		{"Does not match on boolean field",
			map[string]interface{}{"nonMatchingField": "0", "someTrueBooleanField": "false"},
			false},
		{"Has match at top level slice",
			map[string]interface{}{"cms_ids": "A8999|A9990|A9991"},
			true},
		{"Has match on nested map field",
			map[string]interface{}{"someNestedField": map[string]interface{}{"nestedNestedField": map[string]interface{}{"someStringField": "foo|bar"}}},
			true},
		{"No expression field set",
			map[string]interface{}{"nonMatchingField": "foo"},
			false},
		{"Type mismatch - expression has nested fields",
			map[string]interface{}{"someIntegerField": map[string]interface{}{"anotherField": 0}},
			false},
		{"Type mismatch - expression does not have nested fields",
			map[string]interface{}{"someNestedField": 0},
			false},
		{"Invalid regexp",
			map[string]interface{}{"someIntegerField": "["},
			false},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.hasMatch, checkXData(baseXData, convertMap(tt.expression)))
		})
	}
}

func TestTokenCacheTestSuite(t *testing.T) {
	suite.Run(t, new(BlacklistTestSuite))
}

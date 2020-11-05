package blacklist

import (
	"encoding/json"
	"fmt"
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

func (s *BlacklistTestSuite) TestTokenBlacklist() {
	expirationTime := time.Millisecond
	keySet := make(map[string]struct{})
	for len(keySet) < 100 {
		keySet[strconv.Itoa(rand.Int())] = struct{}{}
	}
	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}

	// Pre-seed our blacklist with entries to ensure we skip over any non-matching entries
	for _, key := range keys[50:] {
		s.NoError(s.b.BlacklistToken(key))
	}

	expiredKey := &TokenEntry{Key: keys[0], EntryDate: time.Now().Unix(), CacheExpiration: time.Now().Add(-365 * 24 * time.Hour).UnixNano()}
	s.NoError(s.db.Save(expiredKey).Error)
	notFoundKey, matchingDBExpire, matchingCacheExpire, matchingNoExpire := keys[1], keys[2], keys[3], keys[4]

	noExpire := newBlacklist(72*time.Hour,
		24*time.Minute, time.Millisecond,
		24*time.Hour, expirationTime, // Since we have a 24h expire, we shouldn't expect any entries to age out
		time.Millisecond, 5*time.Minute)
	immediateExpire := newBlacklist(24*time.Hour,
		5*time.Minute, time.Millisecond,
		expirationTime, 24*time.Hour, // Since we have a near zero expiration, we expect the entry to age out immediately.
		5*time.Minute, time.Millisecond)
	cacheExpire := newBlacklist(24*time.Hour,
		time.Millisecond, 5*time.Minute,
		expirationTime, 24*time.Hour, // Since we have a near zero expiration, we expect the entry to age out immediately.
		5*time.Minute, 5*time.Minute) // Set the ticker time to longer to rely on the cache expiration
	defer func() {
		noExpire.close()
		immediateExpire.close()
		cacheExpire.close()
	}()

	tests := []struct {
		name          string
		keyUnderTest  string
		b             *blacklist
		isBlacklisted bool
	}{
		{"ExpiredKeyRewritten", expiredKey.Key, s.b, true},
		{"Matching", matchingNoExpire, noExpire, true},
		{"CacheExpire", matchingCacheExpire, cacheExpire, false},
		{"DBExpire", matchingDBExpire, immediateExpire, false},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			assert.NoError(t, tt.b.BlacklistToken(tt.keyUnderTest))
			<-time.After(2 * expirationTime) // Wait sometime to ensure that expirations work
			assert.Equal(t, tt.isBlacklisted, tt.b.IsTokenBlacklisted(tt.keyUnderTest))
		})
	}

	s.False(s.b.IsTokenBlacklisted(notFoundKey))
}

func (s *BlacklistTestSuite) TestGroupBlacklist() {
	// Pre-seed our blacklist with entries to ensure we skip over any non-matching entries
	extraMatchEntries := []groupEntry{{GroupFieldXData, fmt.Sprintf("{\"%s\":\"%s\", \"%s\":%d}", uuid.New(), uuid.New(), uuid.New(), time.Now().Nanosecond())},
		{GroupFieldXData, fmt.Sprintf("{\"%s\":%d}", uuid.New(), time.Now().Nanosecond()+100)},
		{GroupFieldXData, fmt.Sprintf("{\"%s\":\"%s\"}", uuid.New(), uuid.New())}}
	for _, entry := range extraMatchEntries {
		// Even though we're using the suite blacklist, we're using a shared database.
		// Any newly created blacklist will have these entries populated.
		s.NoError(s.b.BlacklistGroup(entry.field, entry.expression))
	}

	expirationTime := time.Millisecond
	cmsID := uuid.New() // use UUID to avoid deleting data that may not have been created by this test
	group := ssas.Group{XData: `{"cms_ids":["` + cmsID + `"]}`}
	matchingEntry := groupEntry{GroupFieldXData, `{"cms_ids":"` + cmsID + `"}`}
	nonMatchingEntry := groupEntry{GroupFieldXData, `{}`}
	invalidMatchEntry := groupEntry{GroupFieldXData, `{` + cmsID}
	noExpire := newBlacklist(72*time.Hour,
		24*time.Minute, time.Millisecond,
		24*time.Hour, 24*time.Hour, // Since we have a 24h expire, we shouldn't expect any entries to age out
		5*time.Minute, time.Millisecond)
	immediateExpire := newBlacklist(24*time.Hour,
		5*time.Minute, time.Millisecond,
		24*time.Hour, expirationTime, // Since we have a near zero expiration, we expect the entry to age out immediately.
		5*time.Minute, time.Millisecond)
	cacheExpire := newBlacklist(24*time.Hour,
		5*time.Minute, time.Millisecond,
		24*time.Hour, expirationTime, // Since we have a near zero expiration, we expect the entry to age out immediately.
		5*time.Minute, 5*time.Minute) // Set the ticker time to longer to rely on the cache expiration
	defer func() {
		noExpire.close()
		immediateExpire.close()
		cacheExpire.close()
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

			// Clean up any expressions under test to ensure that we do not have older test runs affect later test runs
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

// TestCacheExpiration verifies that we are computing the blacklist cache expiration correctly.
// Before, we were computing a negative cache lifetime which would've resulted in the cache entries never expiring.
func (s *BlacklistTestSuite) TestCacheExpiration() {
	cmsID := uuid.New() // use UUID to avoid deleting data that may not have been created by this test
	group := ssas.Group{XData: `{"cms_ids":["` + cmsID + `"]}`}
	matchingEntry := groupEntry{GroupFieldXData, `{"cms_ids":"` + cmsID + `"}`}

	expiration := 50 * time.Millisecond
	// Create a blacklist with longer refresh times.
	// This'll allow us to better control when the cache refresh occurs.
	b := newBlacklist(72*time.Hour,
		24*time.Hour, 24*time.Hour,
		expiration, expiration,
		24*time.Hour, 24*time.Hour)

	s.NoError(b.BlacklistGroup(matchingEntry.field, matchingEntry.expression))
	s.NoError(b.BlacklistToken(cmsID))
	// Refresh cache. If we've computed the cache duration correctly, we should
	// have the entries expire after the expiration time has elapsed.
	s.NoError(b.loadGroupsFromDatabase())
	s.NoError(b.loadTokensFromDatabase())
	s.True(b.IsGroupBlacklisted(group))
	s.True(b.IsTokenBlacklisted(cmsID))

	<-time.After(2 * expiration)
	s.False(b.IsGroupBlacklisted(group), "Group should no longer be blacklisted")
	s.False(b.IsTokenBlacklisted(cmsID), "Token should no longer be blacklisted")
}
func TestTokenCacheTestSuite(t *testing.T) {
	suite.Run(t, new(BlacklistTestSuite))
}

package blacklist

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/patrickmn/go-cache"
	"github.com/pborman/uuid"
)

// Singleton refresh so we can share a common blacklist instance across various SSAS modules
var Blacklist *blacklist

// This function should only be called by main
func Start() {
	// Guarantee that we only have a single Blacklist instance running
	if Blacklist != nil {
		return
	}
	Blacklist = newBlacklist(24*time.Hour,
		time.Duration(cfg.GetEnvInt("SSAS_TOKEN_BLACKLIST_CACHE_CLEANUP_MINUTES", 15))*time.Minute,
		time.Duration(cfg.GetEnvInt("SSAS_GROUP_BLACKLIST_CACHE_CLEANUP_MINUTES", 15))*time.Minute,
		time.Duration(cfg.GetEnvInt("SSAS_TOKEN_BLACKLIST_CACHE_TIMEOUT_MINUTES", 60*24))*time.Minute,
		time.Duration(cfg.GetEnvInt("SSAS_GROUP_BLACKLIST_CACHE_TIMEOUT_MINUTES", 60*24))*time.Minute,
		time.Duration(cfg.GetEnvInt("SSAS_TOKEN_BLACKLIST_CACHE_REFRESH_MINUTES", 5))*time.Minute,
		time.Duration(cfg.GetEnvInt("SSAS_GROUP_BLACKLIST_CACHE_REFRESH_MINUTES", 5))*time.Minute)
}

// Stop releases any resources allocated by to the singleton blacklist instance
func Stop() {
	if Blacklist == nil {
		return
	}

	Blacklist.close()
	Blacklist = nil
}

func newBlacklist(cacheTimeout time.Duration,
	tokenCleanupInterval, groupCleanupInterval time.Duration,
	tokenCacheLifetime, groupCacheLifetime time.Duration,
	tokenCacheRefresh, groupCacheRefresh time.Duration) *blacklist {

	trackingID := uuid.NewRandom().String()

	bl := blacklist{ID: trackingID, tcLifetime: tokenCacheLifetime, gcLifetime: groupCacheLifetime}

	bl.tc = cache.New(cacheTimeout, tokenCleanupInterval)
	bl.gc = cache.New(cacheTimeout, groupCleanupInterval)

	ssas.OperationStarted(ssas.Event{Op: "InitCacheBlacklist", TrackingID: trackingID})
	if err := bl.loadTokensFromDatabase(); err != nil {
		// Log this failure, but allow the cache to operate.  It's conceivable the next cache refresh will work.
		ssas.CacheSyncFailure(ssas.Event{Op: "BlacklistLoadTokensFromDatabase", TrackingID: trackingID, Help: err.Error()})
	} else {
		ssas.OperationSucceeded(ssas.Event{Op: "InitCacheBlacklist", TrackingID: trackingID})
	}

	ssas.OperationStarted(ssas.Event{Op: "InitGroupBlacklist", TrackingID: trackingID})
	if err := bl.loadGroupsFromDatabase(); err != nil {
		// Log this failure, but allow the cache to operate.  It's conceivable the next cache refresh will work.
		ssas.CacheSyncFailure(ssas.Event{Op: "BlacklistLoadGroupsFromDatabase", TrackingID: trackingID, Help: err.Error()})
	} else {
		ssas.OperationSucceeded(ssas.Event{Op: "InitGroupBlacklist", TrackingID: trackingID})
	}

	bl.tcTicker, bl.tcDone = bl.startCacheRefreshTicker(tokenCacheRefresh, bl.loadTokensFromDatabase)
	bl.gcTicker, bl.gcDone = bl.startCacheRefreshTicker(groupCacheRefresh, bl.loadGroupsFromDatabase)

	return &bl
}

type blacklist struct {
	sync.RWMutex

	tc         *cache.Cache
	tcLifetime time.Duration
	tcTicker   *time.Ticker
	tcDone     chan struct{}

	gc         *cache.Cache
	gcLifetime time.Duration
	gcTicker   *time.Ticker
	gcDone     chan struct{}

	ID string
}

type groupEntry struct {
	field      GroupField
	expression string
}

//	BlacklistToken invalidates the specified tokenID
func (b *blacklist) BlacklistToken(tokenID string) error {
	entryDate := time.Now()
	expirationDate := entryDate.Add(b.tcLifetime)
	if _, err := createTokenEntry(tokenID, entryDate, expirationDate); err != nil {
		return fmt.Errorf(fmt.Sprintf("unable to blacklist token id %s: %s", tokenID, err.Error()))
	}

	// Add to cache only after token is blacklisted in database
	ssas.TokenBlacklisted(ssas.Event{Op: "TokenBlacklist", TrackingID: tokenID, TokenID: tokenID})
	b.tc.Set(tokenID, entryDate.Unix(), b.tcLifetime)

	return nil
}

//	IsTokenBlacklisted tests whether this tokenID is in the blacklist cache.
//	- Tokens should expire before blacklist entries, so a tokenID for a recently expired token may return "true."
//	- This queries the cache only, so if a tokenID has been blacklisted on a different instance, it will return "false"
//		until the cached blacklist is refreshed from the database.
func (b *blacklist) IsTokenBlacklisted(tokenID string) bool {
	b.RLock()
	defer b.RUnlock()

	bEvent := ssas.Event{Op: "TokenVerification", TrackingID: b.ID, TokenID: tokenID}
	if _, found := b.tc.Get(tokenID); found {
		ssas.BlacklistedTokenPresented(bEvent)
		return true
	}
	return false
}

func (b *blacklist) BlacklistGroup(field GroupField, value string) error {
	entryDate := time.Now()
	expirationDate := entryDate.Add(b.gcLifetime)
	entry, err := createGroupEntry(value, entryDate, expirationDate, field)
	if err != nil {
		return fmt.Errorf(fmt.Sprintf("unable to create group blacklist entry value %s: %s", value, err.Error()))
	}

	// Add to cache only after token is blacklisted in database
	ssas.GroupBlacklisted(ssas.Event{Op: "GroupBlacklist", TrackingID: strconv.FormatUint(uint64(entry.ID), 10)})

	b.gc.Set(uuid.New(), groupEntry{field, value}, b.gcLifetime)

	return nil
}

func (b *blacklist) IsGroupBlacklisted(group ssas.Group) bool {
	var cacheItems map[string]cache.Item

	b.RLock()
	cacheItems = b.gc.Items()
	b.RUnlock()

	var xDataObj map[string]interface{}
	if err := json.Unmarshal([]byte(group.XData), &xDataObj); err != nil {
		ssas.OperationFailed(ssas.Event{Op: "XDataUnmarshal", Help: err.Error()})
	}

	for _, item := range cacheItems {
		entry, ok := item.Object.(groupEntry)
		if !ok {
			continue
		}

		switch entry.field {
		case GroupFieldXData:
			// Nothing to compare against
			if xDataObj == nil {
				continue
			}
			var expressionObj map[string]interface{}
			if err := json.Unmarshal([]byte(entry.expression), &expressionObj); err != nil {
				continue
			}
			if checkXData(xDataObj, expressionObj) {
				ssas.BlacklistedGroupPresented(ssas.Event{Op: "GroupVerification", TrackingID: group.GroupID})
				return true
			}
		}
	}

	return false
}

func (b *blacklist) startCacheRefreshTicker(refreshFreq time.Duration, refreshFunc func() error) (ticker *time.Ticker, done chan struct{}) {
	event := ssas.Event{Op: "CacheRefreshTicker", TrackingID: b.ID}
	ssas.ServiceStarted(event)

	ticker = time.NewTicker(refreshFreq)
	done = make(chan struct{})

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := refreshFunc(); err != nil {
					ssas.CacheSyncFailure(ssas.Event{Op: "BlacklistLoadFromDatabase", TrackingID: b.ID, Help: err.Error()})
				}
			}
		}
	}()

	return
}

func (b *blacklist) loadTokensFromDatabase() error {
	var (
		entries []TokenEntry
		err     error
	)

	if entries, err = getUnexpiredTokenEntries(); err != nil {
		return err
	}

	// Need to acquire a lock since we're clearing the entire cache.
	// Any reads in-between us re-hydrating the cache is invalid (false negatives)
	b.Lock()
	defer b.Unlock()

	b.tc.Flush()

	// If the key already exists in the cache, it will be updated.
	for _, entry := range entries {
		cacheDuration := time.Since(time.Unix(0, entry.CacheExpiration))
		b.tc.Set(entry.Key, entry.EntryDate, cacheDuration)
	}
	return nil
}

func (b *blacklist) loadGroupsFromDatabase() error {
	var (
		entries []GroupEntry
		err     error
	)

	if entries, err = getUnexpiredGroupEntries(); err != nil {
		return err
	}

	// Need to acquire a lock since we're clearing the entire cache.
	// Any reads in-between us re-hydrating the cache is invalid (false negatives)
	b.Lock()
	defer b.Unlock()

	b.gc.Flush()

	// If the key already exists in the cache, it will be updated.
	for _, entry := range entries {
		cacheDuration := time.Until(entry.CacheExpiration)
		b.gc.Set(uuid.New(), groupEntry{entry.Field, entry.Expression}, cacheDuration)
	}
	return nil
}

func (b *blacklist) close() error {
	b.tcTicker.Stop()
	b.gcTicker.Stop()
	close(b.tcDone)
	close(b.gcDone)

	return nil
}

// We check any fields found in xdata against any regexp found in expression.
// If any of regexp match, we return true.
func checkXData(xDataObj, expressionObj map[string]interface{}) bool {
	var traverser func(xDataVal, expressionVal interface{}) bool
	traverser = func(xDataVal, expressionVal interface{}) bool {
		// No field to compare against
		if expressionVal == nil {
			return false
		}
		var xDataStr string
		switch reflect.TypeOf(xDataVal).Kind() {
		case reflect.Bool:
			xDataStr = strconv.FormatBool(xDataVal.(bool))
		case reflect.Float64:
			xDataStr = strconv.FormatFloat(xDataVal.(float64), 'f', -1, 64)
		case reflect.String:
			xDataStr = xDataVal.(string)
		case reflect.Slice:
			for _, elem := range xDataVal.([]interface{}) {
				if traverser(elem, expressionVal) {
					return true
				}
			}
		case reflect.Map:
			// Mismatching types
			if reflect.TypeOf(expressionVal).Kind() != reflect.Map {
				return false
			}
			for k, v := range xDataVal.(map[string]interface{}) {
				if traverser(v, expressionVal.(map[string]interface{})[k]) {
					return true
				}
			}
		}

		// Mismatching types
		if reflect.TypeOf(expressionVal).Kind() != reflect.String {
			return false
		}

		exp, err := regexp.Compile(expressionVal.(string))
		if err != nil {
			return false
		}

		return exp.MatchString(xDataStr)
	}

	for key, value := range xDataObj {
		if traverser(value, expressionObj[key]) {
			return true
		}
	}

	return false
}

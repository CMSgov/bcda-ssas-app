package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/patrickmn/go-cache"
	"github.com/pborman/uuid"
)

var (
	TokenBlacklist *Blacklist
	// This default cache timeout value should never be used, since individual cache elements have their own timeouts
	defaultCacheTimeout  = 24 * time.Hour
	cacheCleanupInterval time.Duration
	TokenCacheLifetime   time.Duration
	cacheRefreshFreq     time.Duration

	cacheRefreshTicker *time.Ticker
	cancelFunc         context.CancelFunc // used to clean up resources associated with the ticker
)

func init() {
	cacheCleanupInterval = time.Duration(cfg.GetEnvInt("SSAS_TOKEN_BLACKLIST_CACHE_CLEANUP_MINUTES", 15)) * time.Minute
	TokenCacheLifetime = time.Duration(cfg.GetEnvInt("SSAS_TOKEN_BLACKLIST_CACHE_TIMEOUT_MINUTES", 60*24)) * time.Minute
	cacheRefreshFreq = time.Duration(cfg.GetEnvInt("SSAS_TOKEN_BLACKLIST_CACHE_REFRESH_MINUTES", 5)) * time.Minute
}

// This function should only be called by main
func StartBlacklist() {
	TokenBlacklist = NewBlacklist(defaultCacheTimeout, cacheCleanupInterval)
}

// NewBlacklist allows for easy Blacklist{} creation and manipulation during testing, and, outside a test suite,
// should not be called
func NewBlacklist(cacheTimeout time.Duration, cleanupInterval time.Duration) *Blacklist {
	// In case a Blacklist timer has already been started:
	stopCacheRefreshTicker()

	trackingID := uuid.NewRandom().String()
	event := ssas.Event{Op: "InitBlacklist", TrackingID: trackingID}
	ssas.OperationStarted(event)

	bl := Blacklist{ID: trackingID}
	bl.c = cache.New(cacheTimeout, cleanupInterval)

	if err := bl.LoadFromDatabase(); err != nil {
		event.Help = "unable to load blacklist from database: " + err.Error()
		ssas.OperationFailed(event)
		// Log this failure, but allow the cache to operate.  It's conceivable the next cache refresh will work.
		// Any alerts should be based on the error logged in BlackList.LoadFromDatabase().
	} else {
		ssas.OperationSucceeded(event)
	}

	cacheRefreshTicker, cancelFunc = bl.startCacheRefreshTicker(cacheRefreshFreq)

	return &bl
}

type Blacklist struct {
	sync.RWMutex
	c  *cache.Cache
	ID string
}

// BlacklistToken invalidates the specified tokenID
func (t *Blacklist) BlacklistToken(ctx context.Context, tokenID string, blacklistExpiration time.Duration) error {
	entryDate := time.Now()
	expirationDate := entryDate.Add(blacklistExpiration)
	if _, err := ssas.CreateBlacklistEntry(ctx, tokenID, entryDate, expirationDate); err != nil {
		return fmt.Errorf(fmt.Sprintf("unable to blacklist token id %s: %s", tokenID, err.Error()))
	}

	// Add to cache only after token is blacklisted in database
	ssas.TokenBlacklisted(ssas.Event{Op: "TokenBlacklist", TrackingID: tokenID, TokenID: tokenID})
	t.c.Set(tokenID, entryDate.Unix(), blacklistExpiration)

	return nil
}

// IsTokenBlacklisted tests whether this tokenID is in the blacklist cache.
//   - Tokens should expire before blacklist entries, so a tokenID for a recently expired token may return "true."
//   - This queries the cache only, so if a tokenID has been blacklisted on a different instance, it will return "false"
//     until the cached blacklist is refreshed from the database.
func (t *Blacklist) IsTokenBlacklisted(tokenID string) bool {
	// Ensure that we do not attempt to read when the cache is being rebuilt
	t.RLock()
	defer t.RUnlock()

	bEvent := ssas.Event{Op: "TokenVerification", TrackingID: t.ID, TokenID: tokenID}
	if _, found := t.c.Get(tokenID); found {
		ssas.BlacklistedTokenPresented(bEvent)
		return true
	}
	return false
}

// LoadFromDatabase refreshes unexpired blacklist entries from the database
func (t *Blacklist) LoadFromDatabase() error {
	var (
		entries []ssas.BlacklistEntry
		err     error
	)

	if entries, err = ssas.GetUnexpiredBlacklistEntries(); err != nil {
		ssas.CacheSyncFailure(ssas.Event{Op: "BlacklistLoadFromDatabase", TrackingID: t.ID, Help: err.Error()})
		return err
	}

	// Need to acquire a lock since we're clearing the entire cache.
	// Any reads in-between us re-hydrating the cache is invalid (false negatives)
	t.Lock()
	defer t.Unlock()
	t.c.Flush()

	// If the key already exists in the cache, it will be updated.
	for _, entry := range entries {
		cacheDuration := time.Until(time.Unix(0, entry.CacheExpiration))
		t.c.Set(entry.Key, entry.EntryDate, cacheDuration)
	}
	return nil
}

func (t *Blacklist) startCacheRefreshTicker(refreshFreq time.Duration) (*time.Ticker, context.CancelFunc) {
	event := ssas.Event{Op: "CacheRefreshTicker", TrackingID: t.ID}
	ssas.ServiceStarted(event)

	ticker := time.NewTicker(refreshFreq)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Errors are logged in LoadFromDatabase()
				_ = t.LoadFromDatabase()
			}
		}
	}()

	return ticker, cancel
}

func stopCacheRefreshTicker() {
	if cacheRefreshTicker != nil {
		cacheRefreshTicker.Stop()
		cancelFunc()
	}
}

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
	TokenDenylist      *Denylist
	TokenCacheLifetime time.Duration
	// This default cache timeout value should never be used, since individual cache elements have their own timeouts
	defaultCacheTimeout = 24 * time.Hour

	cacheRefreshTicker *time.Ticker
	cancelFunc         context.CancelFunc // used to clean up resources associated with the ticker
)

type CacheConfig struct {
	cacheCleanupInterval time.Duration
	cacheRefreshFreq     time.Duration
}

func NewCacheConfig() *CacheConfig {
	c := &CacheConfig{
		cacheCleanupInterval: time.Duration(cfg.GetEnvInt("SSAS_TOKEN_DENYLIST_CACHE_CLEANUP_MINUTES", 15)) * time.Minute,
		cacheRefreshFreq:     time.Duration(cfg.GetEnvInt("SSAS_TOKEN_DENYLIST_CACHE_REFRESH_MINUTES", 5)) * time.Minute,
	}
	return c
}

// This function should only be called by main
func StartDenylist() {
	TokenCacheLifetime = time.Duration(cfg.GetEnvInt("SSAS_TOKEN_DENYLIST_CACHE_TIMEOUT_MINUTES", 60*24)) * time.Minute
	c := NewCacheConfig()

	TokenDenylist = NewDenylist(context.Background(), c)
}

func NewDenylist(ctx context.Context, cfg *CacheConfig) *Denylist {
	// In case a Denylist timer has already been started:
	stopCacheRefreshTicker()
	trackingID := uuid.NewRandom().String()

	ssas.Logger.WithField("op", "InitDenylist").Info()
	db, err := ssas.CreateDB()
	if err != nil {
		ssas.Logger.Fatalf("failed to connect to database: %s", err)
	}

	dl := Denylist{ID: trackingID}
	dl.c = cache.New(defaultCacheTimeout, cfg.cacheCleanupInterval)
	dl.r = ssas.NewDenylistEntryRepository(db)
	if err := dl.LoadFromDatabase(); err != nil {
		ssas.Logger.Error("failed to load denylist from database: ", err)
		// Log this failure, but allow the cache to operate.  It's conceivable the next cache refresh will work.
	} else {
		ssas.Logger.Info("successfully loaded denylist from database")
	}

	cacheRefreshTicker, cancelFunc = dl.startCacheRefreshTicker(cfg.cacheRefreshFreq)

	return &dl
}

type Denylist struct {
	sync.RWMutex
	c  *cache.Cache
	ID string
	r  *ssas.DenylistEntryRepository
}

// DenylistToken invalidates the specified tokenID
func (d *Denylist) DenylistToken(ctx context.Context, tokenID string, denylistExpiration time.Duration) error {
	entryDate := time.Now()
	expirationDate := entryDate.Add(denylistExpiration)
	if _, err := d.r.CreateDenylistEntry(ctx, tokenID, entryDate, expirationDate); err != nil {
		return fmt.Errorf("unable to denylist token id %s: %s", tokenID, err.Error())
	}

	// Add to cache only after token is denylisted in database
	d.c.Set(tokenID, entryDate.Unix(), denylistExpiration)

	return nil
}

// IsTokenDenylisted tests whether this tokenID is in the denylist cache.
//   - Tokens should expire before denylist entries, so a tokenID for a recently expired token may return "true."
//   - This queries the cache only, so if a tokenID has been denylisted on a different instance, it will return "false"
//     until the cached denylist is refreshed from the database.
func (d *Denylist) IsTokenDenylisted(tokenID string) bool {
	// Ensure that we do not attempt to read when the cache is being rebuilt
	d.RLock()
	defer d.RUnlock()

	if _, found := d.c.Get(tokenID); found {
		return true
	}
	return false
}

// LoadFromDatabase refreshes unexpired denylist entries from the database
func (d *Denylist) LoadFromDatabase() error {
	var (
		entries []ssas.DenylistEntry
		err     error
	)

	// TODO: pull from configurable setting for db timeout
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if entries, err = d.r.GetUnexpiredDenylistEntries(timeoutCtx); err != nil {
		return err
	}

	// Need to acquire a lock since we're clearing the entire cache.
	// Any reads in-between us re-hydrating the cache is invalid (false negatives)
	d.Lock()
	defer d.Unlock()
	d.c.Flush()

	// If the key already exists in the cache, it will be updated.
	for _, entry := range entries {
		cacheDuration := time.Until(time.Unix(0, entry.CacheExpiration))
		d.c.Set(entry.Key, entry.EntryDate, cacheDuration)
	}
	return nil
}

func (t *Denylist) startCacheRefreshTicker(refreshFreq time.Duration) (*time.Ticker, context.CancelFunc) {
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

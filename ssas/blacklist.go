package ssas

import (
	"context"
	"fmt"
	"time"

	"github.com/pborman/uuid"

	"gorm.io/gorm"
)

type BlacklistEntry struct {
	gorm.Model
	Key             string `gorm:"not null" json:"key"`
	EntryDate       int64  `gorm:"not null" json:"entry_date"`
	CacheExpiration int64  `gorm:"not null" json:"cache_expiration"`
}

func CreateBlacklistEntry(ctx context.Context, key string, entryDate time.Time, cacheExpiration time.Time) (entry BlacklistEntry, err error) {
	event := Event{Op: "CreateBlacklistEntry", TrackingID: key, TokenID: key}
	OperationStarted(event)

	if key == "" {
		err = fmt.Errorf("key cannot be blank")
		event.Help = err.Error()
		OperationFailed(event)
		return
	}

	be := BlacklistEntry{
		Key:             key,
		EntryDate:       entryDate.Unix(),
		CacheExpiration: cacheExpiration.UnixNano(),
	}

	err = Connection.WithContext(ctx).Save(&be).Error
	if err != nil {
		event.Help = err.Error()
		OperationFailed(event)
		return
	}

	OperationSucceeded(event)
	entry = be
	return
}

func GetUnexpiredBlacklistEntries(ctx context.Context) (entries []BlacklistEntry, err error) {
	trackingID := uuid.NewRandom().String()
	event := Event{Op: "GetBlacklistEntries", TrackingID: trackingID}
	OperationStarted(event)

	err = Connection.WithContext(ctx).Order("entry_date, cache_expiration").Where("cache_expiration > ?", time.Now().UnixNano()).Find(&entries).Error
	if err != nil {
		event.Help = err.Error()
		OperationFailed(event)
		return
	}

	OperationSucceeded(event)
	return
}

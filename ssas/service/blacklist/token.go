package blacklist

import (
	"fmt"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/jinzhu/gorm"
	"github.com/pborman/uuid"
)

type TokenEntry struct {
	gorm.Model
	Key             string `gorm:"not null" json:"key"`
	EntryDate       int64  `gorm:"not null" json:"entry_date"`
	CacheExpiration int64  `gorm:"not null" json:"cache_expiration"`
}

// TableName is needed to ensure that we still reference the legacy
// blacklist table name.
// See: https://gorm.io/docs/conventions.html#TableName
func (t TokenEntry) TableName() string {
	return "blacklist_entries"
}

func createTokenEntry(key string, entryDate time.Time, cacheExpiration time.Time) (entry TokenEntry, err error) {
	event := ssas.Event{Op: "createTokenEntry", TrackingID: key, TokenID: key}
	ssas.OperationStarted(event)

	if key == "" {
		err = fmt.Errorf("key cannot be blank")
		event.Help = err.Error()
		ssas.OperationFailed(event)
		return
	}

	be := TokenEntry{
		Key:             key,
		EntryDate:       entryDate.Unix(),
		CacheExpiration: cacheExpiration.UnixNano(),
	}

	db := ssas.GetGORMDbConnection()
	defer ssas.Close(db)
	err = db.Save(&be).Error
	if err != nil {
		event.Help = err.Error()
		ssas.OperationFailed(event)
		return
	}

	ssas.OperationSucceeded(event)
	entry = be
	return
}

func getUnexpiredTokenEntries() (entries []TokenEntry, err error) {
	trackingID := uuid.NewRandom().String()
	event := ssas.Event{Op: "getUnexpiredTokenEntries", TrackingID: trackingID}
	ssas.OperationStarted(event)

	db := ssas.GetGORMDbConnection()
	defer ssas.Close(db)
	err = db.Order("entry_date, cache_expiration").Where("cache_expiration > ?", time.Now().UnixNano()).Find(&entries).Error
	if err != nil {
		event.Help = err.Error()
		ssas.OperationFailed(event)
		return
	}

	ssas.OperationSucceeded(event)
	return
}

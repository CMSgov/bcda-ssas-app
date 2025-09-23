package ssas

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type DenylistEntry struct {
	gorm.Model
	Key             string `gorm:"not null" json:"key"`
	EntryDate       int64  `gorm:"not null" json:"entry_date"`
	CacheExpiration int64  `gorm:"not null" json:"cache_expiration"`
}

type DenylistEntryRepository struct {
	db *gorm.DB
}

func NewDenylistEntryRepository(db *gorm.DB) *DenylistEntryRepository {
	return &DenylistEntryRepository{db: db}
}

func (r *DenylistEntryRepository) CreateDenylistEntry(ctx context.Context, key string, entryDate time.Time, cacheExpiration time.Time) (entry DenylistEntry, err error) {
	if key == "" {
		err = fmt.Errorf("key cannot be blank")
		return
	}

	be := DenylistEntry{
		Key:             key,
		EntryDate:       entryDate.Unix(),
		CacheExpiration: cacheExpiration.UnixNano(),
	}

	err = r.db.WithContext(ctx).Save(&be).Error
	if err != nil {
		return
	}

	entry = be
	return
}

func (r *DenylistEntryRepository) GetUnexpiredDenylistEntries(ctx context.Context) (entries []DenylistEntry, err error) {
	err = r.db.WithContext(ctx).Order("entry_date, cache_expiration").Where("cache_expiration > ?", time.Now().UnixNano()).Find(&entries).Error
	if err != nil {
		return
	}
	return
}

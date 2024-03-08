package ssas

import (
	"context"
	"fmt"
	"time"

	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"

	"gorm.io/gorm"
)

type BlacklistEntry struct {
	gorm.Model
	Key             string `gorm:"not null" json:"key"`
	EntryDate       int64  `gorm:"not null" json:"entry_date"`
	CacheExpiration int64  `gorm:"not null" json:"cache_expiration"`
}

func CreateBlacklistEntry(ctx context.Context, key string, entryDate time.Time, cacheExpiration time.Time) (entry BlacklistEntry, err error) {
	event := logrus.Fields{"Op": "CreateBlacklistEntry", "TrackingID": key, "TokenID": key}
	logger := GetCtxLogger(ctx).WithFields(event)
	logger.Info(OperationStarted)

	if key == "" {
		err = fmt.Errorf("key cannot be blank")
		logger.Error(OperationFailed, logrus.WithField("Help", err.Error()))
		return
	}

	be := BlacklistEntry{
		Key:             key,
		EntryDate:       entryDate.Unix(),
		CacheExpiration: cacheExpiration.UnixNano(),
	}

	err = Connection.WithContext(ctx).Save(&be).Error
	if err != nil {
		logger.Error(OperationFailed, logrus.WithField("Help", err.Error()))
		return
	}

	logger.Info(OperationSucceeded)
	entry = be
	return
}

func GetUnexpiredBlacklistEntries(ctx context.Context) (entries []BlacklistEntry, err error) {
	trackingID := uuid.NewRandom().String()
	event := logrus.Fields{"Op": "GetBlacklistEntries", "TrackingID": trackingID}
	logger := GetCtxLogger(ctx).WithFields(event)
	logger.Info(OperationStarted)

	err = Connection.WithContext(ctx).Order("entry_date, cache_expiration").Where("cache_expiration > ?", time.Now().UnixNano()).Find(&entries).Error
	if err != nil {
		logger.Error(OperationFailed, logrus.WithField("Help", err.Error()))
		return
	}

	logger.Info(OperationSucceeded)
	return
}

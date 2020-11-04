package blacklist

import (
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/jinzhu/gorm"
)

type GroupField string

const (
	GroupFieldXData GroupField = "x_data"
)

type GroupEntry struct {
	gorm.Model
	Expression      string     `gorm:"not null" json:"expression"`
	EntryDate       time.Time  `gorm:"not null" json:"entry_date"`
	CacheExpiration time.Time  `gorm:"not null" json:"cache_expiration"`
	Field           GroupField `gorm:"not null" json:"field"`
}

// TableName is used to define a table name that does not follow GORMs defaults
// See: https://gorm.io/docs/conventions.html#TableName
func (t GroupEntry) TableName() string {
	return "blacklist_group_entries"
}

func createGroupEntry(expression string, entryDate time.Time, cacheExpiration time.Time, field GroupField) (entry GroupEntry, err error) {
	entry = GroupEntry{
		Expression:      expression,
		EntryDate:       entryDate,
		CacheExpiration: cacheExpiration,
		Field:           field,
	}

	db := ssas.GetGORMDbConnection()
	defer ssas.Close(db)

	err = db.Save(&entry).Error
	return
}

func getUnexpiredGroupEntries() (entries []GroupEntry, err error) {
	db := ssas.GetGORMDbConnection()
	defer ssas.Close(db)
	if err = db.Order("entry_date, cache_expiration").Where("cache_expiration > ?", time.Now()).Find(&entries).Error; err != nil {
		return nil, err
	}

	return
}

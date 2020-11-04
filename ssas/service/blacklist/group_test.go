package blacklist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/CMSgov/bcda-ssas-app/ssas"
)

func TestUpsertGroupEntry(t *testing.T) {
	db := ssas.GetGORMDbConnection()
	defer db.Close()

	t0 := time.Now()
	t1 := t0.Add(-24 * time.Hour)
	t2 := t0.Add(24 * time.Hour)

	g1, err := createGroupEntry("e1", t0, t1, GroupFieldXData) 
	assert.NoError(t, err)
	g2, err := createGroupEntry("e1", t0, t2, GroupFieldXData)
	assert.NoError(t, err)

	defer func() {
		assert.NoError(t, db.Unscoped().Delete(&g1).Error)
		assert.NoError(t, db.Unscoped().Delete(&g2).Error)
	}()

	entries, err := getUnexpiredGroupEntries()
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, g2.ID, entries[0].ID)
	assert.NotEqual(t, g1.ID, entries[0].ID)
}

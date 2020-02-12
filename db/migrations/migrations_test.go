// +build migrations

// To run this test suite, run "make migrations-test"
// Make sure to call this suite with an empty test database
package migrations

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"strconv"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	db *gorm.DB
	dbURL string
)

type SchemaMigration struct {
	Version int
	Dirty  bool
}

func TestAllMigrations(t *testing.T) {
	db = ssas.GetGORMDbConnection()
	dbURL = os.Getenv("DATABASE_URL")

	require.True(t, t.Run("up1", up1))
	require.True(t, t.Run("up2", up2))
	require.True(t, t.Run("up3", up3))
	require.True(t, t.Run("up4", up4))
	require.True(t, t.Run("up5", up5))
	// Place all "up" migrations in order above this comment

	// Place all "down" migrations in reverse order below this comment
	require.True(t, t.Run("down5", down5))
	require.True(t, t.Run("down4", down4))
	require.True(t, t.Run("down3", down3))
	require.True(t, t.Run("down2", down2))
	require.True(t, t.Run("down1", down1))
	ssas.Close(db)
}

func up1(t *testing.T) {
	success := runMigration(t, "1")
	assert.True(t, success)

	if success {
		tables := []string{"blacklist_entries", "encryption_keys", "secrets", "systems", "groups"}
		for _, table := range tables {
			if !db.HasTable(table) {
				t.Errorf("table %s was not created", table)
			}
		}
	}
}

func up2(t *testing.T) {
	var group1 ssas.Group
	var g2, g3 ssas.GroupData
	var s1, s2 ssas.System

	err := db.Exec("INSERT INTO groups(group_id) VALUES('A1234')").Error
	assert.Nil(t, err)

	err = db.Exec("INSERT INTO systems(group_id, client_id) VALUES('A1234', 'A1234')").Error
	assert.Nil(t, err)

	success := runMigration(t, "2")
	assert.True(t, success)

	if success {
		group1, err = ssas.GetGroupByGroupID("A1234")
		assert.True(t, group1.ID > 0, "group did not get created")

		// systems.g_id is present, and the values are populated by the "UPDATE" in the migration
		systems, err := ssas.GetSystemsByGroupIDString("A1234")
		assert.Nil(t, err)
		require.Len(t, systems, 1, fmt.Sprintf("looking for 1 system; found %v", len(systems)))
		s1 = systems[0]
		assert.Equal(t, group1.ID, s1.GID)

		// Creating a system with a g_id and without a group_id is allowed
		s2.GID = group1.ID
		s2.ClientID = "system 2"
		err = db.Save(&s2).Error
		assert.Nil(t, err)
		assert.True(t, s2.ID > 0)
		assert.Equal(t, "", s2.GroupID)
		// . . . but put one in anyway to facilitate cleanup
		s2.GroupID = group1.GroupID
		err = db.Save(&s2).Error
		assert.Nil(t, err)

		g2.GroupID = "T0001"
		group2, err := ssas.CreateGroup(g2)
		require.Nil(t, err)
		assert.Equal(t, group2.GroupID, "T0001")

		g3.GroupID = "T0001"
		// We still don't let two undeleted groups have the same group_id . . .
		group3, err := ssas.CreateGroup(g3)
		assert.NotNil(t, err)

		err = ssas.DeleteGroup(strconv.Itoa(int(group2.ID)))
		assert.Nil(t, err)

		// . . . but one can now share the same group_id as a deleted group
		group3, err = ssas.CreateGroup(g3)
		require.Nil(t, err)
		assert.Equal(t, group3.GroupID, "T0001")
		assert.NotEqual(t, group1.ID, group3.ID)

		// Multiple deleted groups should be able to share the same group_id
		err = ssas.DeleteGroup(strconv.Itoa(int(group3.ID)))
		assert.Nil(t, err)

		assert.Nil(t, ssas.CleanDatabase(group1))
		assert.Nil(t, ssas.CleanDatabase(group2))
		assert.Nil(t, ssas.CleanDatabase(group3))
	}
}

func up3(t *testing.T) {
	var group ssas.Group

	success := runMigration(t, "3")
	assert.True(t, success)
	if success {
		group = ssas.Group{GroupID: "test_group_id"}
		err := db.Save(&group).Error
		assert.Nil(t, err)

		system := ssas.System{GID: group.ID, ClientID: "test_client_id"}
		err = db.Save(&system).Error
		assert.Nil(t, err)
		// Trigger no longer populates this field
		assert.Equal(t, "", system.GroupID)
	}

	assert.Nil(t, ssas.CleanDatabase(group))
}

func up4(t *testing.T) {
	success := runMigration(t, "4")
	assert.True(t, success)

	if !db.HasTable("ips") {
		t.Errorf("table ips was not created")
	}
}

func up5(t *testing.T) {
	assert.True(t, runMigration(t, "5"))
	assert.True(t, db.Dialect().HasColumn("systems", "last_token_at"))
}

func down5(t *testing.T) {
	assert.True(t, runMigration(t, "4"))
	assert.False(t, db.Dialect().HasColumn("systems", "last_token_at"))
}

func down4(t *testing.T) {
	success := runMigration(t, "3")
	assert.True(t, success)

	if db.HasTable("ips") {
		t.Errorf("table ips is still present")
	}
}

func down3(t *testing.T) {
	var group ssas.Group

	success := runMigration(t, "2")
	assert.True(t, success)
	if success {
		group = ssas.Group{GroupID: "test_group_id"}
		err := db.Save(&group).Error
		assert.Nil(t, err)

		system := ssas.System{GroupID: group.GroupID, ClientID: "test_client_id"}
		err = db.Save(&system).Error
		assert.Nil(t, err)
		// Trigger automatically populates systems.g_id
		s := ssas.System{ClientID: system.ClientID}
		err = db.Find(&s).Error
		assert.Nil(t, err)

		assert.Equal(t, group.ID, s.GID)
	}

	assert.Nil(t, ssas.CleanDatabase(group))
}

func down2(t *testing.T) {
	var g1, g2 ssas.GroupData
	success := runMigration(t, "1")
	assert.True(t, success)

	if success {
		b := []byte(`{"group_id":"T0002"}`)

		err := json.Unmarshal(b, &g1)
		require.Nil(t, err)
		group1, err := ssas.CreateGroup(g1)
		require.Nil(t, err)
		assert.Equal(t, group1.GroupID, "T0002")
		err = ssas.DeleteGroup(strconv.Itoa(int(group1.ID)))
		assert.Nil(t, err)

		err = json.Unmarshal(b, &g2)
		require.Nil(t, err)
		// This reversion denies deleted groups to share the same group_id as a non-deleted group
		_, err = ssas.CreateGroup(g2)
		assert.NotNil(t, err)
		assert.Nil(t, ssas.CleanDatabase(group1))
	}
}

func down1(t *testing.T) {
	success := true
	// This is a special case, because there is no migration index for what comes before schema 1. Typically,
	// we would want to be certain we're testing the right migration and the next two lines would be replaced by:
	//    success := runMigration(t, "0")
	cmd := exec.Command("migrate", "-verbose", "-database", dbURL, "-path", "./", "down", "1")
	out, err := cmd.Output()
	t.Logf("output from reverting database schema version 1 migration: %s\n", out)
	if err != nil {
		t.Errorf("error reverting database schema version 1 migration: %s; %s\n", err.Error(), out)
		success = false
	}

	if success {
		tables := []string{"blacklist_entries", "encryption_keys", "secrets", "systems", "groups"}
		for _, table := range tables {
			if db.HasTable(table) {
				t.Errorf("table %s was not dropped\n", table)
			}
		}
	}
}

func runMigration(t *testing.T, migrationIndex string) bool {
	cmd := exec.Command("migrate", "-database", dbURL, "-path", "./", "goto", migrationIndex)
	out, err := cmd.CombinedOutput()
	t.Logf("output from migration database schema to version %s: %s\n", migrationIndex, out)
	if err != nil {
		t.Errorf("error migrating database schema to version %s: %s\n", migrationIndex, err.Error())
		return false
	}

	return testIfClean(t, migrationIndex)
}

func testIfClean(t *testing.T, migrationIndex string) bool {
	var migration SchemaMigration

	if _, err := strconv.ParseUint(migrationIndex, 10, 64); err != nil {
		t.Errorf("invalid migration version %s (must be integer value): %s\n", migrationIndex, err.Error())
		return false
	}

	if err := db.Find(&migration, "version = ?", migrationIndex).Error; err != nil {
		t.Errorf("no schema entry found for version %s\n", migrationIndex)
		return false
	}

	return !migration.Dirty
}
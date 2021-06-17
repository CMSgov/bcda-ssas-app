// +build migrations

// To run this test suite, run "make migrations-test"
// Make sure to call this suite with an empty test database
package migrations

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var (
	db    *gorm.DB
	dbURL string
)

type SchemaMigration struct {
	Version int
	Dirty   bool
}

// The tests in this suite need models with specific columns, and cannot indefinitely refer to ssas.System and ssas.Group
type systemv1 struct {
	gorm.Model
	GID            uint                 `json:"g_id"`
	GroupID        string               `json:"group_id"`
	ClientID       string               `json:"client_id"`
	SoftwareID     string               `json:"software_id"`
	ClientName     string               `json:"client_name"`
	APIScope       string               `json:"api_scope"`
	EncryptionKeys []ssas.EncryptionKey `json:"encryption_keys,omitempty" gorm:"foreignkey:SystemID;association_foreignkey:ID"`
	Secrets        []ssas.Secret        `json:"secrets,omitempty" gorm:"foreignkey:SystemID;association_foreignkey:ID"`
}

func (systemv1) TableName() string {
	return "systems"
}

type groupv1 struct {
	gorm.Model
	GroupID string         `gorm:"unique;not null" json:"group_id"`
	XData   string         `gorm:"type:text" json:"xdata"`
	Data    ssas.GroupData `gorm:"type:jsonb" json:"data"`
	Systems []systemv1     `gorm:"foreignkey:GID"`
}

func (groupv1) TableName() string {
	return "groups"
}

func TestAllMigrations(t *testing.T) {
	db = ssas.GetGORMDbConnection()
	dbURL = os.Getenv("DATABASE_URL")

	require.True(t, t.Run("up1", up1))
	require.True(t, t.Run("up2", up2))
	require.True(t, t.Run("up3", up3))
	require.True(t, t.Run("up4", up4))
	require.True(t, t.Run("up5", up5))
	require.True(t, t.Run("up6", up6))
	require.True(t, t.Run("up7", up7))
	// Place all "up" migrations in order above this comment

	// Place all "down" migrations in reverse order below this comment
	require.True(t, t.Run("down7", down7))
	require.True(t, t.Run("down6", down6))
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
			if !db.Migrator().HasTable(table) {
				t.Errorf("table %s was not created", table)
			}
		}
	}
}

func up2(t *testing.T) {
	var group1 groupv1
	var g2, g3 ssas.GroupData
	var s1, s2 systemv1
	var systems []systemv1

	assert.Nil(t, db.Exec("INSERT INTO groups(group_id) VALUES('A1234')").Error)
	assert.Nil(t, db.Exec("INSERT INTO systems(group_id, client_id) VALUES('A1234', 'A1234')").Error)

	success := runMigration(t, "2")
	assert.True(t, success)

	if success {
		err := db.Find(&group1).Where("group_id = ?", "A1234").Error
		assert.True(t, group1.ID > 0, "group did not get created")

		// systems.g_id is present, and the values are populated by the "UPDATE" in the migration
		err = db.Find(&systems).Where("group_id = ?", "A1234").Error
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
		group2, err := ssas.CreateGroup(g2, ssas.RandomHexID())
		require.Nil(t, err)
		assert.Equal(t, group2.GroupID, "T0001")

		g3.GroupID = "T0001"
		// We still don't let two undeleted groups have the same group_id . . .
		group3, err := ssas.CreateGroup(g3, ssas.RandomHexID())
		assert.NotNil(t, err)

		err = ssas.DeleteGroup(strconv.Itoa(int(group2.ID)))
		assert.Nil(t, err)

		// . . . but one can now share the same group_id as a deleted group
		group3, err = ssas.CreateGroup(g3, ssas.RandomHexID())
		require.Nil(t, err)
		assert.Equal(t, group3.GroupID, "T0001")
		assert.NotEqual(t, group1.ID, group3.ID)

		// Multiple deleted groups should be able to share the same group_id
		err = ssas.DeleteGroup(strconv.Itoa(int(group3.ID)))
		assert.Nil(t, err)

		assert.Nil(t, db.Unscoped().Delete(&s1).Error)
		assert.Nil(t, db.Unscoped().Delete(&s2).Error)
		assert.Nil(t, db.Unscoped().Delete(&group1).Error)
		assert.Nil(t, db.Unscoped().Delete(&group2).Error)
		assert.Nil(t, db.Unscoped().Delete(&group3).Error)
	}
}

func up3(t *testing.T) {
	var g groupv1
	var s systemv1

	success := runMigration(t, "3")
	assert.True(t, success)
	if success {
		g = groupv1{GroupID: "test_group_id"}
		err := db.Save(&g).Error
		assert.Nil(t, err)

		s = systemv1{GID: g.ID, ClientID: "test_client_id"}
		err = db.Save(&s).Error
		assert.Nil(t, err)
		// Trigger no longer populates this field
		assert.Equal(t, "", s.GroupID)
	}

	assert.Nil(t, db.Unscoped().Delete(&s).Error)
	assert.Nil(t, db.Unscoped().Delete(&g).Error)
}

func up4(t *testing.T) {
	success := runMigration(t, "4")
	assert.True(t, success)

	if !db.Migrator().HasTable("ips") {
		t.Errorf("table ips was not created")
	}
}

func up5(t *testing.T) {
	assert.True(t, runMigration(t, "5"))
	assert.True(t, db.Migrator().HasColumn(&ssas.System{}, "last_token_at"))
}

func down5(t *testing.T) {
	assert.True(t, runMigration(t, "4"))
	assert.False(t, db.Migrator().HasColumn(&ssas.System{}, "last_token_at"))
}

func up6(t *testing.T) {
	assert.True(t, runMigration(t, "6"))
	assert.True(t, db.Migrator().HasTable("client_tokens"))
}

func down6(t *testing.T) {
	assert.True(t, runMigration(t, "5"))
	assert.False(t, db.Migrator().HasTable("client_tokens"))
}

func up7(t *testing.T) {
	assert.True(t, runMigration(t, "7"))
	assert.True(t, db.Migrator().HasColumn(&ssas.System{}, "x_data"))
}

func down7(t *testing.T) {
	assert.True(t, runMigration(t, "6"))
	assert.False(t, db.Migrator().HasColumn(&ssas.System{}, "x_data"))
}

func down4(t *testing.T) {
	success := runMigration(t, "3")
	assert.True(t, success)

	if db.Migrator().HasTable("ips") {
		t.Errorf("table ips is still present")
	}
}

func down3(t *testing.T) {
	var group groupv1
	var system systemv1

	success := runMigration(t, "2")
	assert.True(t, success)
	if success {
		group = groupv1{GroupID: "test_group_id"}
		err := db.Save(&group).Error
		assert.Nil(t, err)

		system = systemv1{GroupID: group.GroupID, ClientID: "test_client_id"}
		err = db.Save(&system).Error
		assert.Nil(t, err)
		// Trigger automatically populates systems.g_id
		s := ssas.System{ClientID: system.ClientID}
		err = db.Find(&s).Error
		assert.Nil(t, err)

		assert.Equal(t, group.ID, s.GID)
	}

	assert.Nil(t, db.Unscoped().Delete(&system).Error)
	assert.Nil(t, db.Unscoped().Delete(&group).Error)
}

func down2(t *testing.T) {
	success := runMigration(t, "1")
	assert.True(t, success)

	if success {
		g1 := groupv1{GroupID: "T0002"}
		g2 := groupv1{GroupID: "T0002"}

		err := db.Save(&g1).Error
		require.Nil(t, err)
		assert.Equal(t, g1.GroupID, "T0002")

		assert.Nil(t, db.Delete(&g1).Error)

		// This reversion denies deleted groups to share the same group_id as a non-deleted group
		err = db.Save(&g2).Error
		assert.NotNil(t, err)

		assert.Nil(t, db.Unscoped().Delete(&g1).Error)
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
			if db.Migrator().HasTable(table) {
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

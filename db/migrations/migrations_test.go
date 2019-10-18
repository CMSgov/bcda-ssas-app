// +build migrations

// To run this test suite, run "make migrations-test"
// Make sure to call this suite with an empty test database
package migrations

import (
	"os"
	"os/exec"
	"testing"
	"strconv"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/jinzhu/gorm"
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
	dbURL = os.Getenv("DATABASE_URL")
	db = 	ssas.GetGORMDbConnection()

	t.Run("up1", up1)
	//	t.Run("up2", up2)
	// Place all "up" migrations in order above this comment

	// Place all "down" migrations in reverse order below this comment
	//	t.Run("down2", down2)
	t.Run("down1", down1)

	ssas.Close(db)
}

func up1(t *testing.T) {
	success := runMigration(t, "1")

	if success {
		tables := []string{"blacklist_entries", "encryption_keys", "secrets", "systems", "groups"}
		for _, table := range tables {
			if !db.HasTable(table) {
				t.Errorf("table %s was not created", table)
			}
		}
	}
}

func down1(t *testing.T) {
	success := true
	// This is a special case, because there is no migration index for what comes before schema 1. Typically,
	// we would want to be certain we're testing the right migration and the next two lines would be replaced by:
	//    success := runMigration(t, "0")
	cmd := exec.Command("migrate", "-verbose", "-database", dbURL, "-path", "./", "down", "1")
	out, err := cmd.Output()
	t.Logf("output from reverting database schema version 1 migration: %s", out)
	if err != nil {
		t.Errorf("error reverting database schema version 1 migration: %s; %s", err.Error(), out)
		success = false
	}

	if success {
		tables := []string{"blacklist_entries", "encryption_keys", "secrets", "systems", "groups"}
		for _, table := range tables {
			if db.HasTable(table) {
				t.Errorf("table %s was not dropped", table)
			}
		}
	}
}

func runMigration(t *testing.T, migrationIndex string) bool {
	cmd := exec.Command("migrate", "-verbose", "-database", dbURL, "-path", "./", "goto", migrationIndex)
	out, err := cmd.Output()
	t.Logf("output from migration database schema to version %s: %s", migrationIndex, out)
	if err != nil {
		t.Errorf("error migrating database schema to version %s: %s", migrationIndex, err.Error())
		return false
	}

	return testIfClean(t, migrationIndex)
}

func testIfClean(t *testing.T, migrationIndex string) bool {
	var migration SchemaMigration

	if _, err := strconv.ParseUint(migrationIndex, 10, 64); err != nil {
		t.Errorf("invalid migration version %s (must be integer value): %s", migrationIndex, err.Error())
		return false
	}

	if err := db.Find(&migration, "version = ?", migrationIndex).Error; err != nil {
		t.Errorf("no schema entry found for version %s", migrationIndex)
		return false
	}

	return !migration.Dirty
}
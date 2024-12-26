package main

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
)

func TestGetValidIPAddresses(t *testing.T) {
	// insert valid and invalid ip addresses into DB
	dbURL := os.Getenv("DATABASE_URL")
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dbURL)
	assert.Nil(t, err)
	defer conn.Close(ctx)

	var validGroupID, invalidGroupID, validSystemID, invalidSystemID, validSystemID_invalidGroup, validSystemID_invalidSecret, validSystemID_invalidSecret_PastUpdated, secret1, secret2, secret3, ips1, ips2, ips3, ips4, ips5, ips6 int
	conn.QueryRow(ctx, `INSERT INTO groups (group_id) VALUES($1) RETURNING id;`, uuid.New().String()).Scan(&validGroupID)
	conn.QueryRow(ctx, `INSERT INTO groups (group_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, uuid.New().String()).Scan(&invalidGroupID)
	conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID)
	conn.QueryRow(ctx, `INSERT INTO systems (g_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, validGroupID).Scan(&invalidSystemID)
	conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, invalidGroupID).Scan(&validSystemID_invalidGroup)
	conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID_invalidSecret)
	conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID_invalidSecret_PastUpdated)
	conn.QueryRow(ctx, `INSERT INTO secrets (system_id, updated_at) VALUES($1, NOW()) RETURNING id;`, validSystemID).Scan(&secret1)
	conn.QueryRow(ctx, `INSERT INTO secrets (system_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, validSystemID_invalidSecret).Scan(&secret2)
	conn.QueryRow(ctx, `INSERT INTO secrets (system_id, updated_at) VALUES($1, NOW() - INTERVAL '100 DAY') RETURNING id;`, validSystemID_invalidSecret_PastUpdated).Scan(&secret3)
	conn.QueryRow(ctx, `INSERT INTO ips (address, system_id) VALUES('127.0.0.1', $1) RETURNING id;`, validSystemID).Scan(&ips1)
	conn.QueryRow(ctx, `INSERT INTO ips (address, system_id) VALUES('127.0.0.2', $1) RETURNING id;`, validSystemID).Scan(&ips2)
	conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.3', $1, NOW()) RETURNING id;`, invalidSystemID).Scan(&ips3)
	conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.4', $1, NOW()) RETURNING id;`, validSystemID_invalidGroup).Scan(&ips4)
	conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.5', $1, NOW()) RETURNING id;`, validSystemID_invalidSecret).Scan(&ips5)
	conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.6', $1, NOW()) RETURNING id;`, validSystemID_invalidSecret_PastUpdated).Scan(&ips6)

	// test
	addresses, err := getValidIPAddresses(dbURL)
	assert.Nil(t, err)

	assert.Contains(t, addresses, "127.0.0.1/32")
	assert.Contains(t, addresses, "127.0.0.2/32")
	assert.NotContains(t, addresses, "127.0.0.3/32")
	assert.NotContains(t, addresses, "127.0.0.4/32")
	assert.NotContains(t, addresses, "127.0.0.5/32")
	assert.NotContains(t, addresses, "127.0.0.6/32")

	// cleanup
	conn.Exec(ctx, `DELETE FROM ips WHERE id IN($1, $2, $3, $4, $5, $6);`, ips1, ips2, ips3, ips4, ips5, ips6)
	conn.Exec(ctx, `DELETE FROM secrets WHERE id IN($1, $2, $3);`, secret1, secret2, secret3)
	conn.Exec(ctx, `DELETE FROM systems WHERE id IN($1, $2, $3, $4, $5);`, validSystemID, invalidSystemID, validSystemID_invalidGroup, validSystemID_invalidSecret, validSystemID_invalidSecret_PastUpdated)
	conn.Exec(ctx, `DELETE FROM groups WHERE id IN($1, $2);`, validGroupID, invalidGroupID)
}

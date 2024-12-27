package main

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"

	"github.com/pashagolub/pgxmock/v4"
)

func TestGetValidIPAddresses(t *testing.T) {
	ctx := context.Background()
	mock, err := pgxmock.NewConn()
	assert.Nil(t, err)
	defer mock.Close(ctx)

	// the column ips.address returns type net.IP which needs to be handled here like a byte array
	rows := mock.NewRows([]string{"address"}).AddRow([]byte("127.0.0.1"))
	mock.ExpectQuery("^SELECT DISTINCT ips.address FROM ips WHERE (.+)$").WillReturnRows(rows)

	addresses, err := getValidIPAddresses(ctx, mock)
	assert.Nil(t, err)
	// verifying on length of return as byte array from above gets muddled
	assert.Len(t, addresses, 1)
}

func TestGetValidIPAddresses_Integration(t *testing.T) {
	// only run actual DB testing in lower envs
	if slices.Contains([]string{"local", "dev", "test"}, os.Getenv("ENV")) {
		// insert valid and invalid ip addresses into actual DB
		dbURL := os.Getenv("DATABASE_URL")
		ctx := context.Background()

		conn, err := pgx.Connect(ctx, dbURL)
		assert.Nil(t, err)
		defer conn.Close(ctx)

		var validGroupID, invalidGroupID, validSystemID, invalidSystemID, validSystemID_invalidGroup, validSystemID_invalidSecret, validSystemID_invalidSecret_PastUpdated, secret1, secret2, secret3, ips1, ips2, ips3, ips4, ips5, ips6 int
		err = conn.QueryRow(ctx, `INSERT INTO groups (group_id) VALUES($1) RETURNING id;`, uuid.New().String()).Scan(&validGroupID)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO groups (group_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, uuid.New().String()).Scan(&invalidGroupID)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO systems (g_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, validGroupID).Scan(&invalidSystemID)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, invalidGroupID).Scan(&validSystemID_invalidGroup)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID_invalidSecret)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID_invalidSecret_PastUpdated)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO secrets (system_id, updated_at) VALUES($1, NOW()) RETURNING id;`, validSystemID).Scan(&secret1)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO secrets (system_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, validSystemID_invalidSecret).Scan(&secret2)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO secrets (system_id, updated_at) VALUES($1, NOW() - INTERVAL '100 DAY') RETURNING id;`, validSystemID_invalidSecret_PastUpdated).Scan(&secret3)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO ips (address, system_id) VALUES('127.0.0.1', $1) RETURNING id;`, validSystemID).Scan(&ips1)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO ips (address, system_id) VALUES('127.0.0.2', $1) RETURNING id;`, validSystemID).Scan(&ips2)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.3', $1, NOW()) RETURNING id;`, invalidSystemID).Scan(&ips3)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.4', $1, NOW()) RETURNING id;`, validSystemID_invalidGroup).Scan(&ips4)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.5', $1, NOW()) RETURNING id;`, validSystemID_invalidSecret).Scan(&ips5)
		assert.Nil(t, err)
		err = conn.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.6', $1, NOW()) RETURNING id;`, validSystemID_invalidSecret_PastUpdated).Scan(&ips6)
		assert.Nil(t, err)

		// execute
		addresses, err := getValidIPAddresses(ctx, conn)

		// verify
		assert.Nil(t, err)
		assert.Contains(t, addresses, "127.0.0.1/32")
		assert.Contains(t, addresses, "127.0.0.2/32")
		assert.NotContains(t, addresses, "127.0.0.3/32")
		assert.NotContains(t, addresses, "127.0.0.4/32")
		assert.NotContains(t, addresses, "127.0.0.5/32")
		assert.NotContains(t, addresses, "127.0.0.6/32")

		// cleanup
		_, err = conn.Exec(ctx, `DELETE FROM ips WHERE id IN($1, $2, $3, $4, $5, $6);`, ips1, ips2, ips3, ips4, ips5, ips6)
		assert.Nil(t, err)
		_, err = conn.Exec(ctx, `DELETE FROM secrets WHERE id IN($1, $2, $3);`, secret1, secret2, secret3)
		assert.Nil(t, err)
		_, err = conn.Exec(ctx, `DELETE FROM systems WHERE id IN($1, $2, $3, $4, $5);`, validSystemID, invalidSystemID, validSystemID_invalidGroup, validSystemID_invalidSecret, validSystemID_invalidSecret_PastUpdated)
		assert.Nil(t, err)
		_, err = conn.Exec(ctx, `DELETE FROM groups WHERE id IN($1, $2);`, validGroupID, invalidGroupID)
		assert.Nil(t, err)
	}
}

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/CMSgov/bcda-app/bcda/testUtils"
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
	// due to pgxmock being unhappy with any other approach :(
	rows := mock.NewRows([]string{"address"}).AddRow([]byte("127.0.0.1")).AddRow([]byte("1:2:3:4:5:6:7:8"))
	mock.ExpectQuery("^SELECT DISTINCT ips.address FROM ips WHERE (.+)$").WillReturnRows(rows)

	_, ipv6Addresses, err := getValidIPAddresses(ctx, mock)
	assert.Nil(t, err)
	// verifying on length of return as byte array from above gets muddled
	assert.Len(t, ipv6Addresses, 2)
}

func TestGetValidIPAddressesFailure(t *testing.T) {
	ctx := context.Background()
	mock, err := pgxmock.NewConn()
	assert.Nil(t, err)
	defer mock.Close(ctx)

	mock.ExpectQuery("^SELECT DISTINCT ips.address FROM ips WHERE (.+)$").WillReturnError(errors.New("test error"))

	_, _, err = getValidIPAddresses(ctx, mock)
	assert.ErrorContains(t, err, "test error")
}

func TestGetValidIPAddresses_Integration(t *testing.T) {
	ctx := context.Background()
	testUtils.SetParameter(t, fmt.Sprintf("/bcda/%s/api/DATABASE_URL", os.Getenv("ENV")), os.Getenv("DATABASE_URL"))

	// insert valid and invalid ip addresses into actual DB
	dbURL, err := getDBURL(context.Background())
	assert.Nil(t, err)
	conn, err := pgx.Connect(ctx, dbURL)
	assert.Nil(t, err)
	defer conn.Close(ctx)

	tx, err := conn.Begin(context.Background())
	assert.Nil(t, err)

	var validGroupID, invalidGroupID, validSystemID, invalidSystemID, validSystemID_invalidGroup, validSystemID_invalidSecret, validSystemID_invalidSecret_PastUpdated, secret1, secret2, secret3, ips1, ips2, ips3, ips4, ips5, ips6, ipv6Valid, ipv6Invalid int
	err = tx.QueryRow(ctx, `INSERT INTO groups (group_id) VALUES($1) RETURNING id;`, uuid.New().String()).Scan(&validGroupID)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO groups (group_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, uuid.New().String()).Scan(&invalidGroupID)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO systems (g_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, validGroupID).Scan(&invalidSystemID)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, invalidGroupID).Scan(&validSystemID_invalidGroup)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID_invalidSecret)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO systems (g_id) VALUES($1) RETURNING id;`, validGroupID).Scan(&validSystemID_invalidSecret_PastUpdated)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO secrets (system_id, updated_at) VALUES($1, NOW()) RETURNING id;`, validSystemID).Scan(&secret1)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO secrets (system_id, deleted_at) VALUES($1, NOW()) RETURNING id;`, validSystemID_invalidSecret).Scan(&secret2)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO secrets (system_id, updated_at) VALUES($1, NOW() - INTERVAL '100 DAY') RETURNING id;`, validSystemID_invalidSecret_PastUpdated).Scan(&secret3)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id) VALUES('127.0.0.1', $1) RETURNING id;`, validSystemID).Scan(&ips1)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id) VALUES('127.0.0.2', $1) RETURNING id;`, validSystemID).Scan(&ips2)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.3', $1, NOW()) RETURNING id;`, invalidSystemID).Scan(&ips3)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.4', $1, NOW()) RETURNING id;`, validSystemID_invalidGroup).Scan(&ips4)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.5', $1, NOW()) RETURNING id;`, validSystemID_invalidSecret).Scan(&ips5)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES('127.0.0.6', $1, NOW()) RETURNING id;`, validSystemID_invalidSecret_PastUpdated).Scan(&ips6)
	assert.Nil(t, err)

	testipv6Valid := "ecc3:92b5:56a4:84af:d086:4671:b091:1681"
	testipv6Invalid := "b0b7:ed8f:348f:13d2:92b0:b018:9c57:4dc9"
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id) VALUES($1, $2) RETURNING id;`, testipv6Valid, validSystemID).Scan(&ipv6Valid)
	assert.Nil(t, err)
	err = tx.QueryRow(ctx, `INSERT INTO ips (address, system_id, deleted_at) VALUES($1, $2, NOW()) RETURNING id;`, testipv6Invalid, invalidSystemID).Scan(&ipv6Invalid)
	assert.Nil(t, err)

	// execute
	addresses, ipv6Addresses, err := getValidIPAddresses(ctx, tx)

	// verify
	assert.Nil(t, err)
	assert.Contains(t, addresses, "127.0.0.1/32")
	assert.Contains(t, addresses, "127.0.0.2/32")
	assert.NotContains(t, addresses, "127.0.0.3/32")
	assert.NotContains(t, addresses, "127.0.0.4/32")
	assert.NotContains(t, addresses, "127.0.0.5/32")
	assert.NotContains(t, addresses, "127.0.0.6/32")
	assert.Contains(t, ipv6Addresses, testipv6Valid+"/128")
	assert.NotContains(t, ipv6Addresses, testipv6Invalid+"/128")

	// cleanup
	err = tx.Rollback(ctx)
	assert.Nil(t, err)
}

func TestGetDbAddress(t *testing.T) {
	testUtils.SetParameter(t, fmt.Sprintf("/bcda/%s/api/DATABASE_URL", os.Getenv("ENV")), "test-url")

	dbURL, err := getDBURL(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, "test-url", dbURL)
}

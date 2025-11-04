package main

import (
	"context"
	"testing"

	"github.com/CMSgov/bcda-app/bcda/testUtils"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
)

func TestUpdateIpSet(t *testing.T) {
	ctx := context.Background()
	wafClient := wafv2.NewFromConfig(testUtils.TestAWSConfig(t))
	mock, err := pgxmock.NewConn()
	assert.Nil(t, err)
	defer mock.Close(ctx)

	// the column ips.address returns type net.IP which needs to be handled here like a byte array
	// due to pgxmock being unhappy with any other approach :(
	rows := mock.NewRows([]string{"address"}).AddRow([]byte("127.0.0.1"))
	mock.ExpectQuery("^SELECT DISTINCT ips.address FROM ips WHERE (.+)$").WillReturnRows(rows)

	addrs, err := updateIpSet(ctx, mock, wafClient)
	assert.Nil(t, err)
	// has 4 entries as our WAF mock is returning specific hardcoded values
	assert.Len(t, addrs, 4)
}

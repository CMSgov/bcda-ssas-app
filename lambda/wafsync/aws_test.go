package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchAndUpdateIpAddresses(t *testing.T) {
	ctx := context.Background()
	wafClient := &mockWAFV2Client{}

	addresses, err := fetchAndUpdateIpAddresses(ctx, wafClient, "test-ip-set", []string{"127.0.0.1/32", "127.0.0.2/32"})

	assert.Nil(t, err)
	assert.Contains(t, addresses, "127.0.0.1/32")
	assert.Contains(t, addresses, "127.0.0.2/32")
}

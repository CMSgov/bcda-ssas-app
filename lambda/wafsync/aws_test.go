package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	"github.com/CMSgov/bcda-app/bcda/testUtils"
)

func TestFetchAndUpdateIpAddresses(t *testing.T) {
	ctx := context.Background()
	wafClient := wafv2.NewFromConfig(testUtils.TestAWSConfig(t))

	input := &wafv2.CreateIPSetInput{
		Addresses:        []string{},
		IPAddressVersion: "IPV4",
		Name:             aws.String("test-ip-set"),
		Scope:            "REGIONAL",
	}
	output, err := wafClient.CreateIPSet(ctx, input)
	assert.Nil(t, err)
	t.Cleanup(func() {
		_, err := wafClient.DeleteIPSet(ctx, &wafv2.DeleteIPSetInput{
			Id:        output.Summary.Id,
			LockToken: output.Summary.LockToken,
			Name:      aws.String("test-ip-set"),
			Scope:     "REGIONAL",
		})
		assert.Nil(t, err)
	})

	addresses, err := fetchAndUpdateIpAddresses(ctx, wafClient, "test-ip-set", []string{"127.0.0.1/32", "127.0.0.2/32"})

	assert.Nil(t, err)
	assert.Contains(t, addresses, "127.0.0.1/32")
	assert.Contains(t, addresses, "127.0.0.2/32")
}

func TestFetchAndUpdateIpAddresses_NoIPSet(t *testing.T) {
	ctx := context.Background()
	wafClient := wafv2.NewFromConfig(testUtils.TestAWSConfig(t))

	addresses, err := fetchAndUpdateIpAddresses(ctx, wafClient, "test-ip-set", []string{"127.0.0.1/32", "127.0.0.2/32"})

	assert.ErrorContains(t, err, "failed to get expected ip address set")
	assert.Equal(t, nil, addresses)
}

func TestFetchAndUpdateIpAddresses_BadIPAddresses(t *testing.T) {
	ctx := context.Background()
	wafClient := wafv2.NewFromConfig(testUtils.TestAWSConfig(t))

	addresses, err := fetchAndUpdateIpAddresses(ctx, wafClient, "test-ip-set", []string{"asdf", "-%+90"})

	assert.ErrorContains(t, err, "failed to update ip address set")
	assert.Equal(t, nil, addresses)
}

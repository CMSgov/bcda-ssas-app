package main

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
	"github.com/stretchr/testify/assert"
)

// mock waf v2 client with related mocked/dummy functions below
type mockWAFV2Client struct {
	wafv2iface.WAFV2API
}

func (m *mockWAFV2Client) ListIPSets(input *wafv2.ListIPSetsInput) (*wafv2.ListIPSetsOutput, error) {
	return &wafv2.ListIPSetsOutput{}, nil
}

func (m *mockWAFV2Client) GetIPSet(input *wafv2.GetIPSetInput) (*wafv2.GetIPSetOutput, error) {
	return &wafv2.GetIPSetOutput{IPSet: &wafv2.IPSet{
		ARN: aws.String("randomtwentycharacterstring"),
		// unfortunately we have to hardcode the ip addresses we are testing for as the flow of the logic
		// is ListIpSets -> GetIPSet -> UpdateIPSet -> GetIPSet (to verify updates and output changes to logs)
		Addresses:        aws.StringSlice([]string{"127.0.0.1/32", "127.0.0.2/32"}),
		IPAddressVersion: aws.String("v2"),
		Id:               aws.String("id"),
		Name:             aws.String("name"),
	}}, nil
}

func (m *mockWAFV2Client) UpdateIPSet(input *wafv2.UpdateIPSetInput) (*wafv2.UpdateIPSetOutput, error) {
	return &wafv2.UpdateIPSetOutput{}, nil
}

func TestNewSession(t *testing.T) {
	tests := []struct {
		err        error
		newSession func(cfgs ...*aws.Config) (*session.Session, error)
	}{
		{
			// Happy path
			err:        nil,
			newSession: func(cfgs ...*aws.Config) (*session.Session, error) { return nil, nil },
		},
		{
			// Error returned from NewSession
			err:        errors.New("error"),
			newSession: func(cfgs ...*aws.Config) (*session.Session, error) { return nil, errors.New("error") },
		},
	}

	for _, test := range tests {
		newSession := test.newSession
		sess, err := newSession(aws.NewConfig())

		assert.Nil(t, sess)
		assert.Equal(t, test.err, err)
	}
}

func TestNewLocalSession(t *testing.T) {
	tests := []struct {
		err                   error
		newSessionWithOptions func(opts session.Options) (*session.Session, error)
	}{
		{
			// Happy path
			err:                   nil,
			newSessionWithOptions: func(opts session.Options) (*session.Session, error) { return nil, nil },
		},
		{
			// Error returned from NewSessionWithOptions
			err:                   errors.New("error"),
			newSessionWithOptions: func(opts session.Options) (*session.Session, error) { return nil, errors.New("error") },
		},
	}

	for _, test := range tests {
		newSessionWithOptions := test.newSessionWithOptions

		sess, err := newSessionWithOptions(session.Options{})

		assert.Nil(t, sess)
		assert.Equal(t, test.err, err)
	}
}

// happy path testing only due to business logic flow
func TestUpdateIpAddresses(t *testing.T) {
	mock := &mockWAFV2Client{}

	addresses, err := updateIpAddresses(mock, []string{"127.0.0.1/32", "127.0.0.2/32"})

	assert.Nil(t, err)
	assert.Contains(t, addresses, "127.0.0.1/32")
	assert.Contains(t, addresses, "127.0.0.2/32")
}

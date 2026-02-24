package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

type mockWAFV2 interface {
	ListIPSets(ctx context.Context, params *wafv2.ListIPSetsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListIPSetsOutput, error)
	GetIPSet(ctx context.Context, params *wafv2.GetIPSetInput, optFns ...func(*wafv2.Options)) (*wafv2.GetIPSetOutput, error)
	UpdateIPSet(ctx context.Context, params *wafv2.UpdateIPSetInput, optFns ...func(*wafv2.Options)) (*wafv2.UpdateIPSetOutput, error)
}

type mockWAFV2Client struct{}

func (m *mockWAFV2Client) ListIPSets(ctx context.Context, params *wafv2.ListIPSetsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListIPSetsOutput, error) {
	output := &wafv2.ListIPSetsOutput{
		IPSets: []types.IPSetSummary{
			{
				Id:   aws.String("1"),
				Name: aws.String("test-ip-set"),
			},
		},
	}
	return output, nil
}

func (m *mockWAFV2Client) GetIPSet(ctx context.Context, params *wafv2.GetIPSetInput, optFns ...func(*wafv2.Options)) (*wafv2.GetIPSetOutput, error) {
	output := &wafv2.GetIPSetOutput{
		IPSet: &types.IPSet{
			Addresses: []string{"127.0.0.1/32", "127.0.0.2/32"},
		},
	}
	return output, nil
}

func (m *mockWAFV2Client) UpdateIPSet(ctx context.Context, params *wafv2.UpdateIPSetInput, optFns ...func(*wafv2.Options)) (*wafv2.UpdateIPSetOutput, error) {
	return &wafv2.UpdateIPSetOutput{}, nil
}

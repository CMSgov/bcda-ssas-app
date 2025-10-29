package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	log "github.com/sirupsen/logrus"
)

func fetchAndUpdateIpAddresses(ctx context.Context, client *wafv2.Client, ipSetName string, ipAddresses []string) ([]string, error) {
	listParams := &wafv2.ListIPSetsInput{
		Scope: "REGIONAL",
	}
	ipSetList, err := client.ListIPSets(ctx, listParams)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ip address sets, %v", err)
	}

	log.WithField("name", ipSetName).Info("Fetching IP set")
	getParams := &wafv2.GetIPSetInput{
		Name:  &ipSetName,
		Scope: "REGIONAL",
	}
	for _, ipSet := range ipSetList.IPSets {
		if *ipSet.Name == ipSetName {
			getParams.Id = ipSet.Id
			break
		}
	}
	ipSet, err := client.GetIPSet(ctx, getParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get expected ip address set, %+v", err)
	}

	updateParams := &wafv2.UpdateIPSetInput{
		Id:          ipSet.IPSet.Id,
		Name:        aws.String(ipSetName),
		Scope:       "REGIONAL",
		LockToken:   ipSet.LockToken,
		Addresses:   ipAddresses,
		Description: aws.String("IP ranges for customers of this API"),
	}
	_, err = client.UpdateIPSet(ctx, updateParams)
	if err != nil {
		return nil, fmt.Errorf("failed to update ip address set, %+v", err)
	}

	addrs := []string{}
	ipSet, err = client.GetIPSet(ctx, getParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get expected ip address set, %+v", err)
	}
	for _, addr := range ipSet.IPSet.Addresses {
		addrs = append(addrs, addr)
	}

	return addrs, nil
}

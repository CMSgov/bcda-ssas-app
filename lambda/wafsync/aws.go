package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
	log "github.com/sirupsen/logrus"
)

type Parameters struct {
	Id        string
	Name      string
	Scope     string
	LockToken string
	Addresses []string
}

func fetchAndUpdateIpAddresses(waf wafv2iface.WAFV2API, ipSetName string, ipAddresses []string) ([]string, error) {
	listParams := &wafv2.ListIPSetsInput{
		Scope: aws.String("REGIONAL"),
	}
	ipSetList, err := waf.ListIPSets(listParams)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ip address sets, %v", err)
	}

	log.WithField("name", ipSetName).Info("Fetching IP set")
	getParams := &wafv2.GetIPSetInput{
		Name:  &ipSetName,
		Scope: aws.String("REGIONAL"),
	}
	for _, ipSet := range ipSetList.IPSets {
		if *ipSet.Name == ipSetName {
			getParams.Id = ipSet.Id
			break
		}
	}
	ipSet, err := waf.GetIPSet(getParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get expected ip address set, %+v", err)
	}

	updateParams := &wafv2.UpdateIPSetInput{
		Id:          ipSet.IPSet.Id,
		Name:        aws.String(ipSetName),
		Scope:       aws.String("REGIONAL"),
		LockToken:   ipSet.LockToken,
		Addresses:   aws.StringSlice(ipAddresses),
		Description: aws.String("IP ranges for customers of this API"),
	}
	_, err = waf.UpdateIPSet(updateParams)
	if err != nil {
		return nil, fmt.Errorf("failed to update ip address set, %+v", err)
	}

	addrs := []string{}
	ipSet, err = waf.GetIPSet(getParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get expected ip address set, %+v", err)
	}
	for _, addr := range ipSet.IPSet.Addresses {
		addrs = append(addrs, *addr)
	}

	return addrs, nil
}

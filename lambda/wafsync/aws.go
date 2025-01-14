package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
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

var createSession = func() (*session.Session, error) {
	sess := session.Must(session.NewSession())

	var err error
	if isTesting {
		sess, err = session.NewSessionWithOptions(session.Options{
			Profile: "default",
			Config: aws.Config{
				Region:           aws.String("us-east-1"),
				S3ForcePathStyle: aws.Bool(true),
				Endpoint:         aws.String("http://localhost:4566"),
			},
		})
	}
	if err != nil {
		return nil, err
	}

	return sess, nil
}

func fetchAndUpdateIpAddresses(waf wafv2iface.WAFV2API, ipAddresses []string) ([]string, error) {
	ipSetName := fmt.Sprintf("bcda-%s-api-customers", os.Getenv("ENV"))

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

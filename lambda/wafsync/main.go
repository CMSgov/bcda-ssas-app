package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/aws/aws-sdk-go/service/wafv2/wafv2iface"
	"github.com/jackc/pgx/v5"

	log "github.com/sirupsen/logrus"
)

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, event events.S3Event) error {
	log.Info("Starting WAF Sync Lambda")

	log.SetFormatter(&log.JSONFormatter{
		DisableHTMLEscape: true,
		TimestampFormat:   time.RFC3339Nano,
	})

	dbURL, err := getDBURL()
	if err != nil {
		log.Errorf("Unable to extract DB URL from parameter store: %+v", err)
		return err
	}

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Errorf("Unable to connect to database: %+v", err)
		return err
	}
	defer conn.Close(ctx)

	sess := session.Must(session.NewSession())
	wafsvc := wafv2.New(sess, &aws.Config{
		Region: aws.String("us-east-1"),
	})

	_, err = updateIpSet(ctx, conn, wafsvc)
	if err != nil {
		return err
	}

	log.Info("Completed WAF Sync lambda")

	return nil
}

func updateIpSet(ctx context.Context, conn PgxConnection, wafsvc wafv2iface.WAFV2API) ([]string, error) {
	// get valid IPv4 and IPv6 addresses
	ipAddresses, ipv6Addresses, err := getValidIPAddresses(ctx, conn)
	if err != nil {
		log.Errorf("Error getting valid IP addresses: %+v", err)
		return nil, err
	}

	// update IPv4 WAF IP set
	ipSetName := fmt.Sprintf("bcda-%s-api-customers", os.Getenv("ENV"))
	ipv4Addrs, err := fetchAndUpdateIpAddresses(wafsvc, ipSetName, ipAddresses)
	if err != nil {
		log.Errorf("Error updating IP addresses: %+v", err)
		return nil, err
	}

	// update IPv6 IP set
	ipv6SetName := fmt.Sprintf("bcda-%s-ipv6-api-customers", os.Getenv("ENV"))
	ipv6Addrs, err := fetchAndUpdateIpAddresses(wafsvc, ipv6SetName, ipv6Addresses)
	if err != nil {
		log.Errorf("Error updating IP addresses: %+v", err)
		return nil, err
	}

	// set up return of all addresses
	var addresses []string
	addresses = append(addresses, ipv4Addrs...)
	addresses = append(addresses, ipv6Addrs...)

	if len(addresses) == 0 {
		log.WithField("name", ipSetName).Error("length of IP addresses to update is 0, potentially problematic")
	}

	return addresses, nil
}

package main

import (
	"context"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

var isTesting = os.Getenv("IS_TESTING") == "true"

func main() {
	if isTesting {
		var addresses, err = updateIpSet()
		if err != nil {
			log.Error(err)
		} else {
			log.Println(addresses)
		}
	} else {
		lambda.Start(handler)
	}
}

func handler(ctx context.Context, event events.S3Event) ([]string, error) {
	log.Info("Starting WAF Sync Lambda")

	log.SetFormatter(&log.JSONFormatter{
		DisableHTMLEscape: true,
		TimestampFormat:   time.RFC3339Nano,
	})

	var addrs, err = updateIpSet()
	if err != nil {
		return nil, err
	}

	log.Info("Completed WAF Sync lambda")

	return addrs, nil
}

func updateIpSet() ([]string, error) {
	dbURL := os.Getenv("DATABASE_URL")
	ipAddresses, err := getValidIPAddresses(dbURL)
	if err != nil {
		log.Errorf("Error getting valid IP addresses: %+v", err)
		return nil, err
	}

	addresses, err := updateIpAddresses(ipAddresses)
	if err != nil {
		log.Errorf("Error updating IP addresses: %+v", err)
		return nil, err
	}

	return addresses, nil
}

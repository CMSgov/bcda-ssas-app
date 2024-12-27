package main

import (
	"context"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/jackc/pgx/v5"

	log "github.com/sirupsen/logrus"
)

var isTesting = os.Getenv("IS_TESTING") == "true"

func main() {
	if isTesting {
		var addresses, err = updateIpSet(context.Background())
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

	var addrs, err = updateIpSet(ctx)
	if err != nil {
		return nil, err
	}

	log.Info("Completed WAF Sync lambda")

	return addrs, nil
}

func updateIpSet(ctx context.Context) ([]string, error) {
	dbURL := os.Getenv("DATABASE_URL")
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Errorf("Unable to connect to database: %+v", err)
		return nil, err
	}

	ipAddresses, err := getValidIPAddresses(ctx, conn)
	if err != nil {
		log.Errorf("Error getting valid IP addresses: %+v", err)
		return nil, err
	}

	sess, err := createSession()
	if err != nil {
		log.Errorf("Failed creating session to update ip set, %+v", err)
		return nil, err
	}

	wafsvc := wafv2.New(sess, &aws.Config{
		Region: aws.String("us-east-1"),
	})

	addresses, err := updateIpAddresses(wafsvc, ipAddresses)
	if err != nil {
		log.Errorf("Error updating IP addresses: %+v", err)
		return nil, err
	}

	return addresses, nil
}

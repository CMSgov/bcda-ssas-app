package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	log "github.com/sirupsen/logrus"

	bcdaaws "github.com/CMSgov/bcda-app/bcda/aws"
	"github.com/CMSgov/bcda-app/bcda/constants"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

type PgxConnection interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
	Prepare(context.Context, string, string) (*pgconn.StatementDescription, error)
}

func getValidIPAddresses(ctx context.Context, conn PgxConnection) ([]string, []string, error) {
	query := `
		SELECT DISTINCT ips.address FROM ips
		WHERE deleted_at IS NULL
		AND system_id IN (
			SELECT systems.id
			FROM secrets
			JOIN systems ON secrets.system_id = systems.id
			JOIN groups ON systems.g_id = groups.id
			WHERE secrets.deleted_at IS NULL AND
				systems.deleted_at IS NULL AND
				groups.deleted_at IS NULL AND
				secrets.updated_at > (current_date - interval '90' day)
		)
	`
	rows, err := conn.Query(ctx, query)
	if err != nil {
		log.Errorf("Error running query: %+v", err)
		return nil, nil, err
	}

	// count seems to only be used to log num of rows for debugging
	count := 0
	ipAddresses := []string{}
	ipv6Addresses := []string{}
	defer rows.Close()

	for rows.Next() {
		var ip net.IP

		err = rows.Scan(&ip)
		if err != nil {
			log.Errorf("Scan error: %+v", err)
			return nil, nil, err
		}

		count += 1
		if count%10000 == 0 {
			log.Infof("Read %d rows", count)
		}

		// check if ip address is IPv4 or IPv6
		if ip.To4() != nil {
			ipAddresses = append(ipAddresses, ip.String()+"/32")
		} else {
			ipv6Addresses = append(ipv6Addresses, ip.String()+"/128")
		}

	}

	log.WithField("num_rows_scanned", count).Info("Successfully retrieved valid IP addresses")

	return ipAddresses, ipv6Addresses, nil
}

func getDBURL(ctx context.Context) (string, error) {
	env := os.Getenv("ENV")

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(constants.DefaultRegion),
	)
	if err != nil {
		return "", err
	}
	ssmClient := ssm.NewFromConfig(cfg)

	return bcdaaws.GetParameter(ctx, ssmClient, fmt.Sprintf("/bcda/%s/api/DATABASE_URL", env))
}

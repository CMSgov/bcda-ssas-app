package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/CMSgov/bcda-app/conf"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	log "github.com/sirupsen/logrus"

	bcdaaws "github.com/CMSgov/bcda-app/bcda/aws"
)

type PgxConnection interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
	Ping(context.Context) error
	Prepare(context.Context, string, string) (*pgconn.StatementDescription, error)
	Close(context.Context) error
}

func getValidIPAddresses(ctx context.Context, conn PgxConnection) ([]string, error) {
	defer conn.Close(ctx)

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
		return nil, err
	}

	// count seems to only be used to log num of rows for debugging
	count := 0
	ipAddresses := []string{}
	defer rows.Close()

	for rows.Next() {
		var ip net.IP

		err = rows.Scan(&ip)
		if err != nil {
			log.Warningf("Scan error: %+v", err)
			return nil, err
		}

		count += 1
		if count%10000 == 0 {
			log.Infof("Read %d rows", count)
		}

		ipAddresses = append(ipAddresses, ip.String()+"/32")
	}

	log.WithField("num_rows_scanned", count).Info("Successfully retrieved valid IP addresses")

	return ipAddresses, nil
}

func getDBURL() (string, error) {
	env := conf.GetEnv("ENV")

	bcdaSession, err := bcdaaws.NewSession("", os.Getenv("LOCAL_STACK_ENDPOINT"))
	if err != nil {
		return "", err
	}

	param, err := bcdaaws.GetParameter(bcdaSession, fmt.Sprintf("/bcda/%s/api/DATABASE_URL", env))
	if err != nil {
		return "", err
	}

	return param, nil
}

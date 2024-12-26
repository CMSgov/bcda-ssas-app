package main

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
)

func getValidIPAddresses(dbURL string) ([]string, error) {
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Errorf("Unable to connect to database: %+v", err)
		return nil, err
	}
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

		// Not sure why we need this
		count += 1
		if count%10000 == 0 {
			log.Infof("Read %d rows", count)
		}

		fmt.Printf("\nRow found in function!: %+v\n", ip)

		ipAddresses = append(ipAddresses, fmt.Sprintf("%s/32", ip))
	}

	log.WithField("num_rows_scanned", count).Info("Successfully retrieved valid IP addresses")

	return ipAddresses, nil
}

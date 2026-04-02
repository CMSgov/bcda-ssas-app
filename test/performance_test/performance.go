package main

import (
	"flag"
	"os"
)

var (
	clientID       string
	clientSecret   string
	apiHost        string
	proto          string
	reportFilePath string
	endpoint       string

	freq     int
	duration int
)

func init() {
	flag.StringVar(&clientID, "clientID", "", "client id for retrieving an access token")
	flag.StringVar(&clientSecret, "clientSecret", "", "client secret for retrieving an access token")
	flag.StringVar(&apiHost, "host", "localhost:3004", "host to send requests to")
	flag.IntVar(&duration, "duration", 60, "seconds: the total time to run the test")
	flag.IntVar(&freq, "freq", 10, "the number of requests per second")
	flag.StringVar(&proto, "proto", "http", "protocol to use")
	flag.StringVar(&reportFilePath, "report_path", "../../test_results/performance", "path to write the result.html")
	flag.StringVar(&endpoint, "endpoint", "token", "endpoint to test ('token' or 'introspect')")
	flag.Parse()

	// create folder if doesn't exist for storing the results
	if _, err := os.Stat(reportFilePath); os.IsNotExist(err) {
		err := os.MkdirAll(reportFilePath, 0744)
		if err != nil {
			panic(err)
		}
	}
}


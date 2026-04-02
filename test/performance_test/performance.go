package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	vegeta "github.com/tsenart/vegeta/v12/lib"
	"github.com/tsenart/vegeta/v12/lib/plot"
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

func main() {
	if clientID == "" || clientSecret == "" {
		log.Fatal("clientID and clientSecret must be provided")
	}

	var targeter vegeta.Targeter

	if endpoint == "token" {
		targeter = makeTokenTarget()
	} else if endpoint == "introspect" {
		targeter = makeIntrospectTarget(testToken)
	} else {
		log.Fatalf("Unknown endpoint: %s. Use 'token' or 'introspect'", endpoint)
	}
	results := runPerformanceTest(targeter)
}

func makeTokenTarget() vegeta.Targeter {
	url := fmt.Sprintf("%s://%s/token", proto, apiHost)

	// Prepare basic auth header
	req, _ := http.NewRequest("POST", url, nil)
	req.SetBasicAuth(clientID, clientSecret)
	authHeader := req.Header.Get("Authorization")

	header := map[string][]string{
		"Accept":        {"application/json"},
		"Authorization": {authHeader},
		"User-Agent":    {"bcda-ssas-performance-test"},
	}

	return vegeta.NewStaticTargeter(vegeta.Target{
		Method: "POST",
		URL:    url,
		Header: header,
	})
}

func makeIntrospectTarget(accessToken string) vegeta.Targeter {
	url := fmt.Sprintf("%s://%s/introspect", proto, apiHost)

	// Prepare basic auth header
	req, _ := http.NewRequest("POST", url, nil)
	req.SetBasicAuth(clientID, clientSecret)
	authHeader := req.Header.Get("Authorization")

	header := map[string][]string{
		"Accept":        {"application/json"},
		"Content-Type":  {"application/json"},
		"Authorization": {authHeader},
		"User-Agent":    {"bcda-ssas-performance-test"},
	}

	body := map[string]string{
		"token": accessToken,
	}
	bodyBytes, _ := json.Marshal(body)

	return vegeta.NewStaticTargeter(vegeta.Target{
		Method: "POST",
		URL:    url,
		Header: header,
		Body:   bodyBytes,
	})
}
func runPerformanceTest(target vegeta.Targeter) *plot.Plot {
	fmt.Printf("running performance test for: %s\n", endpoint)
	title := plot.Title(fmt.Sprintf("Performance Test - %s", endpoint))
	p := plot.New(title)
	defer p.Close()
	return p
}


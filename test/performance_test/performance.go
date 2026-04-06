package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

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
	insecure bool
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
	flag.BoolVar(&insecure, "insecure", false, "ignore certificates")
	flag.Parse()

	// create folder if doesn't exist for storing the results
	if _, err := os.Stat(reportFilePath); os.IsNotExist(err) {
		err := os.MkdirAll(reportFilePath, 0750)
		if err != nil {
			panic(err)
		}
	}
}

func main() {
	if clientID == "" || clientSecret == "" {
		log.Fatal("clientID and clientSecret must be provided")
	}

	if strings.HasPrefix(apiHost, "http://") {
		proto = "http"
		apiHost = strings.TrimPrefix(apiHost, "http://")
	} else if strings.HasPrefix(apiHost, "https://") {
		proto = "https"
		apiHost = strings.TrimPrefix(apiHost, "https://")
	}

	var targeter vegeta.Targeter

	switch endpoint {
	case "token":
		targeter = makeTokenTarget()
	case "introspect":
		testToken := getAccessToken(clientID, clientSecret)
		targeter = makeIntrospectTarget(testToken)
	default:
		log.Fatalf("Unknown endpoint: %s. Use 'token' or 'introspect'", endpoint)
	}

	results, metrics := runPerformanceTest(targeter)
	var buf bytes.Buffer
	_, err := results.WriteTo(&buf)
	if err != nil {
		panic(err)
	}

	timestamp := time.Now().Format("20060102150405")

	// Write HTML results
	writeResults(fmt.Sprintf("%s_api_plot_%s.html", endpoint, timestamp), buf.Bytes())

	// Write JSON results
	reporter := vegeta.NewJSONReporter(metrics)
	var jsonBuf bytes.Buffer
	if err := reporter(&jsonBuf); err != nil {
		panic(err)
	}
	writeResults(fmt.Sprintf("%s_api_plot_%s.json", endpoint, timestamp), jsonBuf.Bytes())
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

func runPerformanceTest(target vegeta.Targeter) (*plot.Plot, *vegeta.Metrics) {
	fmt.Printf("running performance test for: %s\n", endpoint)
	title := plot.Title(fmt.Sprintf("Performance Test - %s", endpoint))
	p := plot.New(title)
	defer p.Close()

	d := time.Second * time.Duration(duration)
	rate := vegeta.Rate{Freq: freq, Per: time.Second}
	var metrics vegeta.Metrics
	defer func() {
		// Needed to compute all of the summary metrics
		metrics.Close()
		if err := validateMetrics(metrics); err != nil {
			log.Printf("Validation error: %s", err.Error())
		}
	}()
	plotAttack(p, &metrics, target, rate, d)

	return p, &metrics
}

func plotAttack(p *plot.Plot, m *vegeta.Metrics, t vegeta.Targeter, r vegeta.Rate, du time.Duration) {
	attacker := vegeta.NewAttacker(
		vegeta.TLSConfig(&tls.Config{InsecureSkipVerify: insecure}), //nolint:gosec
	)
	for results := range attacker.Attack(t, r, du, fmt.Sprintf("%dps:", r.Freq)) {
		if err := p.Add(results); err != nil {
			panic(err)
		}
		m.Add(results)
	}
}

func writeResults(filename string, data []byte) {
	re := regexp.MustCompile(`[^a-zA-Z0-9\.\-]`)
	clean := re.ReplaceAllString(filename, "-")
	if len(data) > 0 {
		fn := fmt.Sprintf("%s/%s", reportFilePath, clean)
		fmt.Printf("Writing results: %s\n", fn)
		err := os.WriteFile(fn, data, 0600)
		if err != nil {
			panic(err)
		}
	}
}

func getAccessToken(cID, cSecret string) string {
	req, err := http.NewRequest("POST", fmt.Sprintf("%s://%s/token", proto, apiHost), nil)
	if err != nil {
		panic(err)
	}

	req.SetBasicAuth(cID, cSecret)
	req.Header.Add("Accept", "application/json")

	fmt.Printf("Fetching test access token for introspect test...\n")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req) //nolint:gosec
	if err != nil {
		panic(fmt.Sprintf("failed to get token: %s", err.Error()))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("failed to get token: received status code %d", resp.StatusCode))
	}

	var t map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&t); err != nil {
		panic(fmt.Sprintf("unexpected token response format: %s", err.Error()))
	}

	tokenStr, ok := t["access_token"].(string)
	if !ok {
		panic("access_token missing or not a string in response")
	}
	return tokenStr
}

func validateMetrics(metrics vegeta.Metrics) error {
	if metrics.Requests == 0 {
		return nil
	}

	if len(metrics.Errors) > 0 {
		return fmt.Errorf("encountered %v errors", metrics.Errors)
	}

	if metrics.Success < 1.0 {
		return fmt.Errorf("expected success rate of 1.0, received %f",
			metrics.Success)
	}

	return nil
}

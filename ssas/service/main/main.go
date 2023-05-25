/*
	Package main System-to-System Authentication Service

	The System-to-System Authentication Service (SSAS) enables one software system to authenticate and authorize another software system. In this model, the Systems act automatically, independent of a human user identity. Human users are involved only to administer the Service, including establishing the identities and privileges of participating systems.

	For more details see our repository readme and Postman tests:
	- https://github.com/CMSgov/bcda-ssas-app
	- https://github.com/CMSgov/bcda-ssas-app/tree/master/test/postman_test

	If you have a Client ID and Secret you can use this page to explore the API.  To do this, click the green "Authorize" button below and enter your Client ID and secret in the Basic Authentication username and password boxes.

Until you click logout your token will be presented with every request made.  To make requests click on the "Try it out" button for the desired endpoint.

	    Version: 1.0.0
	    License: Public Domain https://github.com/CMSgov/bcda-ssas-app/blob/master/LICENSE.md
	    Contact: bcapi@cms.hhs.gov

	    Produces:
	    - application/json

	    SecurityDefinitions:
	    basic_auth:
	         type: basic

	swagger:meta
*/
package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/CMSgov/bcda-ssas-app/ssas/service/admin"
	"github.com/CMSgov/bcda-ssas-app/ssas/service/public"
	"github.com/go-chi/chi/v5"
	gcmw "github.com/go-chi/chi/v5/middleware"
	"github.com/newrelic/go-agent/v3/newrelic"
	"gorm.io/gorm"
)

var doAddFixtureData bool
var doResetSecret bool
var doNewAdminSystem bool
var doListIPs bool
var doListExpCreds bool
var doShowXData bool
var doStart bool
var clientID string
var auth string
var systemName string
var output io.Writer

func init() {
	output = os.Stdout

	const usageAddFixtureData = "unconditionally add fixture data"
	flag.BoolVar(&doAddFixtureData, "add-fixture-data", false, usageAddFixtureData)

	const usageResetSecret = "reset system secret for the given client_id; requires client-id flag with argument"
	flag.BoolVar(&doResetSecret, "reset-secret", false, usageResetSecret)

	const usageNewAdminSystem = "add a new admin system to the service; requires system-name flag with argument"
	flag.BoolVar(&doNewAdminSystem, "new-admin-system", false, usageNewAdminSystem)
	flag.StringVar(&systemName, "system-name", "", "the system's name (e.g., 'BCDA Admin')")

	const usageListIPs = "list all IP addresses registered to active systems"
	flag.BoolVar(&doListIPs, "list-ips", false, usageListIPs)

	const usageListExpCreds = "list credentials about to expire or timeout due to inactivity"
	flag.BoolVar(&doListExpCreds, "list-exp-creds", false, usageListExpCreds)

	const usageShowXData = "display group xdata"
	flag.BoolVar(&doShowXData, "show-xdata", false, usageShowXData)
	flag.StringVar(&auth, "auth", "", "an auth header containing the hashed client id")

	const usageStart = "start the service"
	flag.BoolVar(&doStart, "start", false, usageStart)

	// used by both `doResetSecret` and `doGetXdata`
	flag.StringVar(&clientID, "client-id", "", "a system's client id")

	appName := os.Getenv("NEW_RELIC_APP_NAME")
	licenseKey := os.Getenv("NEW_RELIC_LICENSE_KEY")
	_, err := newrelic.NewApplication(
		newrelic.ConfigAppName(appName),
		newrelic.ConfigLicense(licenseKey),
	)
	if nil != err {
		ssas.Logger.Warnf("New Relic integration is disabled: %s", err)
	}
}

// We provide some simple commands for bootstrapping the system into place. Commands cannot be combined.
func main() {
	ssas.Logger.Info("Home of the System-to-System Authentication Service")

	flag.Parse()
	if doAddFixtureData {
		addFixtureData()
		return
	}
	if doResetSecret && clientID != "" {
		resetSecret(clientID)
		return
	}
	if doNewAdminSystem && systemName != "" {
		newAdminSystem(systemName)
		return
	}
	if doListIPs {
		listIPs()
		return
	}
	if doListExpCreds {
		listExpiringCredentials()
		return
	}
	if doShowXData && (clientID != "" || auth != "") {
		if clientID != "" || auth != "" {
			err := showXData(clientID, auth)
			if err != nil {
				ssas.Logger.Error(err)
			}
		} else {
			ssas.Logger.Error("`show-xdata` requires either the client-id or auth key arg be set")
		}
		return
	}
	if doStart {
		start()
		return
	}
}

func start() {
	ssas.Logger.Infof("%s", "Starting ssas...")

	ps := public.Server()
	if ps == nil {
		ssas.Logger.Error("unable to create public server")
		os.Exit(-1)
	}
	ps.LogRoutes()
	ps.Serve()

	as := admin.Server()
	if as == nil {
		ssas.Logger.Error("unable to create admin server")
		os.Exit(-1)
	}
	as.LogRoutes()
	as.Serve()

	service.StartBlacklist()

	// Accepts and redirects HTTP requests to HTTPS. Not sure we should do this.
	forwarder := &http.Server{
		Handler:           newForwardingRouter(),
		Addr:              ":3005",
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	ssas.Logger.Fatal(forwarder.ListenAndServe())
}

func newForwardingRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(gcmw.RequestID, service.NewAPILogger(), service.ConnectionClose)
	r.Get("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// TODO only forward requests for paths in our own host or resource server
		url := "https://" + req.Host + req.URL.String()
		ssas.Logger.Infof("forwarding from %s to %s", req.Host+req.URL.String(), url)
		http.Redirect(w, req, url, http.StatusMovedPermanently)
	}))
	return r
}

func addFixtureData() {
	db := ssas.Connection

	if err := db.Save(&ssas.Group{GroupID: "admin"}).Error; err != nil {
		fmt.Println(err)
	}
	// group for cms_id A9994; client_id 0c527d2e-2e8a-4808-b11d-0fa06baf8254
	if err := db.Save(&ssas.Group{GroupID: "0c527d2e-2e8a-4808-b11d-0fa06baf8254", Data: ssas.GroupData{GroupID: "0c527d2e-2e8a-4808-b11d-0fa06baf8254"}, XData: `{"cms_ids":["A9994"]}`}).Error; err != nil {
		fmt.Println(err)
	}
	makeSystem(db, "admin", "31e029ef-0e97-47f8-873c-0e8b7e7f99bf",
		"BCDA API Admin", "bcda-admin",
		"ofSsVmNaR6+nq93pGUhzKcLvJlokzE4mKqBxS8kt5Fc=:yt+N0wLzqZsY4Lw0pIEWlySbU7y7P7mNnn8IUjsZR0qis9/X2aKtjAMKlFRcCp+CYDeF/+FrvzuCDqacQwX+hA==:130000",
	)
	makeSystem(db, "0c527d2e-2e8a-4808-b11d-0fa06baf8254",
		"0c527d2e-2e8a-4808-b11d-0fa06baf8254", "ACO Dev", "bcda-api",
		"bUtFIoldpvBjK92JoJrZEQCZbjTAI0o5RRJ+krdHMFA=:iKOi8/rskQ+ykmA32f3iVNQ6SWBJbWrC0weq7K6R1LF164zKcmQ8PXa4CMUZ1kd8sBBqvP+ISTYqwDu9C+5dtA==:130000")
}

func makeSystem(db *gorm.DB, groupID, clientID, clientName, scope, hash string) {
	pem := `-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhxobShmNifzW3xznB+L
	I8+hgaePpSGIFCtFz2IXGU6EMLdeufhADaGPLft9xjwdN1ts276iXQiaChKPA2CK
	/CBpuKcnU3LhU8JEi7u/db7J4lJlh6evjdKVKlMuhPcljnIKAiGcWln3zwYrFCeL
	cN0aTOt4xnQpm8OqHawJ18y0WhsWT+hf1DeBDWvdfRuAPlfuVtl3KkrNYn1yqCgQ
	lT6v/WyzptJhSR1jxdR7XLOhDGTZUzlHXh2bM7sav2n1+sLsuCkzTJqWZ8K7k7cI
	XK354CNpCdyRYUAUvr4rORIAUmcIFjaR3J4y/Dh2JIyDToOHg7vjpCtNnNoS+ON2
	HwIDAQAB
	-----END PUBLIC KEY-----`

	g, err := ssas.GetGroupByGroupID(groupID)
	if err != nil {
		ssas.Logger.Warn(err)
	}

	system := ssas.System{GID: g.ID, GroupID: groupID, ClientID: clientID, ClientName: clientName, APIScope: scope}
	if err := db.Save(&system).Error; err != nil {
		ssas.Logger.Warn(err)
	}

	encryptionKey := ssas.EncryptionKey{
		Body:     pem,
		SystemID: system.ID,
	}
	if err := db.Save(&encryptionKey).Error; err != nil {
		ssas.Logger.Warn(err)
	}

	secret := ssas.Secret{
		Hash:     hash,
		SystemID: system.ID,
	}
	if err := db.Save(&secret).Error; err != nil {
		ssas.Logger.Warn(err)
	}
}

func resetSecret(clientID string) {
	var (
		err error
		s   ssas.System
		c   ssas.Credentials
	)
	if s, err = ssas.GetSystemByClientID(clientID); err != nil {
		ssas.Logger.Warn(err)
	}
	ssas.OperationCalled(ssas.Event{Op: "ResetSecret", TrackingID: cliTrackingID(), Help: "calling from main.resetSecret()"})
	if c, err = s.ResetSecret(clientID); err != nil {
		ssas.Logger.Warn(err)
	} else {
		_, _ = fmt.Fprintf(output, "%s\n", c.ClientSecret)
	}
}

func newAdminSystem(name string) {
	var (
		err error
		pk  string
		c   ssas.Credentials
		u   uint64
	)
	if pk, _, _, err = ssas.GeneratePublicKey(2048); err != nil {
		ssas.Logger.Errorf("no public key; %s", err)
		return
	}

	trackingID := cliTrackingID()
	ssas.OperationCalled(ssas.Event{Op: "RegisterSystem", TrackingID: trackingID, Help: "calling from main.newAdminSystem()"})
	if c, err = ssas.RegisterSystem(name, "admin", "bcda-api", pk, []string{}, trackingID); err != nil {
		ssas.Logger.Error(err)
		return
	}

	if u, err = strconv.ParseUint(c.SystemID, 10, 64); err != nil {
		ssas.Logger.Errorf("invalid systemID %d; %s", u, err)
		return
	}

	db := ssas.Connection

	if err = db.Model(&ssas.System{}).Where("id = ?", uint(u)).Update("api_scope", "bcda-admin").Error; err != nil {
		ssas.Logger.Warnf("bcda-admin scope not set for new system %s", c.SystemID)
	} else {
		_, _ = fmt.Fprintf(output, "%s\n", c.ClientID)
	}
}

func listIPs() {
	ips, err := ssas.GetAllIPs()
	if err != nil {
		panic("unable to get registered IPs")
	}
	listOfIps := strings.Join(ips, "\n")
	fmt.Fprintln(output, listOfIps)
	ssas.Logger.Infof("Retrieving registered IPs: %s", listOfIps)
}

func listExpiringCredentials() {
	db := ssas.Connection

	type result struct {
		ClientID    string     `json:"client_id"`
		GroupID     string     `json:"group_id"`
		XData       string     `json:"x_data"`
		LastTokenAt *time.Time `json:"last_token_at,omitempty"`
		Timeout     *time.Time `json:"timeout,omitempty"`
		Expiration  *time.Time `json:"expiration"`
	}

	timeoutDays := cfg.GetEnvInt("SSAS_CRED_TIMEOUT_DAYS", 60)
	expirationDays := cfg.GetEnvInt("SSAS_CRED_EXPIRATION_DAYS", 90)
	warningDays := cfg.GetEnvInt("SSAS_CRED_WARNING_DAYS", 7)

	// Retrieve all active credentials about to expire or timeout, and report:
	// 1) When the credentials expire (which is based on when they were created)
	// 2) When inactivity would time out the credentials (which is based on the last time they were used to create a token)
	rows, err := db.Raw(
		`
			SELECT 
				client_id, 
				groups.group_id, 
				groups.x_data, 
				last_token_at, 
				COALESCE(last_token_at, secrets.created_at) + ? * interval '1 day' as "timeout", 
				secrets.created_at + ? * interval '1 day' as "expiration" 
			FROM secrets 
				JOIN systems ON secrets.system_id = systems.id 
				JOIN groups ON systems.g_id = groups.id 
			WHERE secrets.deleted_at IS NULL 
				AND systems.deleted_at IS NULL 
				AND (COALESCE(last_token_at, secrets.created_at) + ? * interval '1 day' < now() + ? * interval '1 day' 
					OR secrets.created_at + ? * interval '1 day' < now() + ? * interval '1 day') 
			ORDER BY expiration;
		`, timeoutDays, expirationDays, timeoutDays, warningDays, expirationDays, warningDays).Rows()
	defer closeRows(rows)
	if err != nil {
		panic("unable to get expiring credentials: " + err.Error())
	}
	for rows.Next() {
		var row result
		err = db.ScanRows(rows, &row)
		if err != nil {
			panic("error parsing credentials: " + err.Error())
		}
		o, err := json.Marshal(row)
		if err != nil {
			panic("unable to marshal expiring credentials: " + err.Error())
		}
		fmt.Fprintln(output, string(o))
	}
}

func closeRows(rows *sql.Rows) {
	_ = rows.Close()
}

func cliTrackingID() string {
	return fmt.Sprintf("cli-command-%d", time.Now().Unix())
}

func showXData(clientID, auth string) error {
	// The auth header decoding logic was pulled from Go's requuest.go#parseBasicAuth func
	if auth != "" {
		c, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return fmt.Errorf("unable to decode the auth hash: %w", err)
		}

		cs := string(c)
		// Get length of string up to colon in string (ie the client id length)
		s := strings.IndexByte(cs, ':')
		if s < 0 {
			return errors.New("no client id present after decoding auth hash")
		}

		clientID = cs[:s]
	}

	system, err := ssas.GetSystemByClientID(clientID)
	if err != nil {
		return fmt.Errorf("invalid client id: %w", err)
	}

	group, err := ssas.GetGroupByGroupID(system.GroupID)
	if err != nil {
		return fmt.Errorf("unable to find group with id %v: %w", system.GroupID, err)
	}

	fmt.Fprintln(output, group.XData)

	return nil
}

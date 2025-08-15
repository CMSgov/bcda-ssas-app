package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

type MainTestSuite struct {
	suite.Suite
	db *gorm.DB
}

func (s *MainTestSuite) SetupSuite() {
	s.db = ssas.Connection
}

func (s *MainTestSuite) TestResetSecret() {
	var flags Flags
	flags.doResetSecret = true
	flags.clientID = service.TestGroupID
	output := captureOutput(func() { handleFlags(flags) })
	assert.NotEqual(s.T(), "", output)
}

func (s *MainTestSuite) TestResetSecretBadClientID() {
	var flags Flags
	flags.doResetSecret = true
	flags.clientID = "This client does not exist"
	output := captureOutput(func() { handleFlags(flags) })
	assert.Equal(s.T(), "", output)
}

func (s *MainTestSuite) TestShowXDataWithClientID() {
	creds, _ := ssas.CreateTestXData(s.T(), s.db)

	var flags Flags
	flags.doShowXData = true
	flags.clientID = creds.ClientID
	output := captureOutput(func() { handleFlags(flags) })
	assert.Equal(s.T(), "{\"group\":\"1\"}\n", output)
}

func (s *MainTestSuite) TestShowXDataClientIDDoesNotExist() {
	var flags Flags
	flags.doShowXData = true
	flags.clientID = "bad-id"
	output := captureLog(func() { handleFlags(flags) })
	assert.Contains(s.T(), output, "invalid client id")
}

func (s *MainTestSuite) TestShowXDataSystemGroupIDDoesNotExist() {
	creds, _ := ssas.CreateTestXData(s.T(), s.db)
	sys, err := ssas.GetSystemByID(context.Background(), creds.SystemID)
	assert.Nil(s.T(), err)

	sys.GroupID = ""
	err = s.db.Save(&sys).Error
	assert.Nil(s.T(), err)

	var flags Flags
	flags.doShowXData = true
	flags.clientID = creds.ClientID
	output := captureLog(func() { handleFlags(flags) })
	assert.Contains(s.T(), output, "no Group record found for groupID")
}

func (s *MainTestSuite) TestShowXDataWithAuth() {
	creds, _ := ssas.CreateTestXData(s.T(), s.db)

	// Build encoded api key to mimic auth header
	auth := base64.StdEncoding.EncodeToString([]byte(creds.ClientID + ":" + creds.ClientSecret))

	var flags Flags
	flags.doShowXData = true
	flags.auth = auth
	output := captureOutput(func() { handleFlags(flags) })
	assert.Equal(s.T(), "{\"group\":\"1\"}\n", output)
}

func (s *MainTestSuite) TestShowXDataWithInvalidBase64() {
	var flags Flags
	flags.doShowXData = true
	flags.auth = "12%123"
	output := captureLog(func() { handleFlags(flags) })
	assert.Contains(s.T(), output, "unable to decode the auth hash")
}

func (s *MainTestSuite) TestShowXDataWithInvalidAuth() {
	var flags Flags
	flags.doShowXData = true
	flags.auth = "1234"
	output := captureLog(func() { handleFlags(flags) })
	assert.Contains(s.T(), output, "no client id present after decoding auth hash")
}

func (s *MainTestSuite) TestShowXDataWithoutParameters() {
	var flags Flags
	flags.doShowXData = true
	output := captureLog(func() { handleFlags(flags) })
	assert.Contains(s.T(), output, "requires either the client-id or auth key")
}

func (s *MainTestSuite) TestAddFixtureData() {
	var flags Flags
	flags.doAddFixtureData = true
	output := captureLog(func() { handleFlags(flags) })
	assert.Contains(s.T(), output, "ERROR")
}

func (s *MainTestSuite) TestResetCredentials() {
	var flags Flags
	flags.doResetSecret = true
	flags.clientID = service.TestGroupID

	output := captureOutput(func() { handleFlags(flags) })
	assert.NotEqual(s.T(), output, "")
}

func (s *MainTestSuite) TestNewAdminSystem() {
	var flags Flags
	flags.doNewAdminSystem = true
	flags.systemName = "Main Test System"
	output := captureOutput(func() { handleFlags(flags) })
	assert.NotEqual(s.T(), "", output)
}

func (s *MainTestSuite) TestMainLog() {
	main()
	content, err := os.ReadFile(os.Getenv("SSAS_LOG"))
	assert.Nil(s.T(), err)
	assert.Contains(s.T(), string(content), "Home of")
}

func (s *MainTestSuite) TestFixtureData() {
	q := `select distinct g.id as gid, g.group_id, s.id as sid, s.client_name, ek.id as ekid, s.id as scrtid
	from groups g
	join systems s on g.group_id = s.group_id
	join encryption_keys ek on ek.system_id = s.id
	join secrets sc on sc.system_id = s.id
	where g.group_id in ('admin', '0c527d2e-2e8a-4808-b11d-0fa06baf8254');`
	// if you run the query above against the db, you will see a result like this:
	// gid |               group_id               | sid |  client_name   | ekid | scrtid
	// -----+--------------------------------------+-----+----------------+------+--------
	// 15 | admin                                |  13 | BCDA API Admin |   13 |     13
	// 16 | 0c527d2e-2e8a-4808-b11d-0fa06baf8254 |  14 | ACO Dev        |   14 |     14
	// (2 rows)
	//
	// only complete fixture data will be included in the result

	type result struct {
		GID        uint   `json:"gid"`
		GroupID    string `json:"group_id"`
		SID        uint   `json:"sid"`
		ClientName string `json:"client_name"`
		EKID       uint   `json:"ekid"`
		ScrtID     uint   `json:"scrtid"`
	}
	rows, err := ssas.Connection.Raw(q).Rows()
	require.Nil(s.T(), err, "error checking fixture data")
	defer rows.Close()

	foundAdmin := false
	foundConsumer := false
	for rows.Next() {
		var r result
		err := rows.Scan(&r.GID, &r.GroupID, &r.SID, &r.ClientName, &r.EKID, &r.ScrtID)
		require.Nil(s.T(), err, "error scanning data")
		switch r.GroupID {
		case "admin":
			foundAdmin = true
		case service.TestGroupID:
			foundConsumer = true
		}
	}

	assert.True(s.T(), foundAdmin)
	assert.True(s.T(), foundConsumer)
}

func (s *MainTestSuite) TestListIPs() {
	db := ssas.Connection
	fixtureClientID := service.TestGroupID
	system, err := ssas.GetSystemByClientID(context.Background(), fixtureClientID)
	assert.Nil(s.T(), err)
	testIP := ssas.RandomIPv4()
	ip := ssas.IP{
		Address:  testIP,
		SystemID: system.ID,
	}
	err = db.Save(&ip).Error
	assert.Nil(s.T(), err)
	var str bytes.Buffer
	logger := ssas.GetLogger(ssas.Logger)
	logger.SetOutput(&str)

	var flags Flags
	flags.doListIPs = true
	cliOutput := captureOutput(func() { handleFlags(flags) })
	output := str.String()
	assert.NotContains(s.T(), output, "unable to get registered IPs")
	assert.Contains(s.T(), output, testIP)
	assert.Contains(s.T(), cliOutput, testIP)
	defer assert.Nil(s.T(), db.Unscoped().Delete(&ip).Error)
}

func (s *MainTestSuite) TestListExpiringCredentials() {
	var secret ssas.Secret
	db := ssas.Connection

	assert.Nil(s.T(), os.Setenv("SSAS_CRED_EXPIRATION_DAYS", "90"))
	assert.Nil(s.T(), os.Setenv("SSAS_CRED_TIMEOUT_DAYS", "60"))
	assert.Nil(s.T(), os.Setenv("SSAS_CRED_WARNING_DAYS", "7"))

	fixtureClientID := service.TestGroupID
	system, err := ssas.GetSystemByClientID(context.Background(), fixtureClientID)
	assert.Nil(s.T(), err)
	assert.False(s.T(), errors.Is(db.First(&secret, "system_id = ?", system.ID).Error, gorm.ErrRecordNotFound))
	origCreatedAt := secret.CreatedAt
	origLastTokenAt := system.LastTokenAt

	var flags Flags
	flags.doListExpCreds = true

	// Credentials that will expire but not timeout during the warning period WILL be shown
	secret.CreatedAt = time.Now().Add(-84 * 24 * time.Hour)
	system.LastTokenAt = time.Now().Add(-52 * 24 * time.Hour)
	assert.Nil(s.T(), db.Save(&system).Error)
	assert.Nil(s.T(), db.Save(&secret).Error)
	output := captureOutput(func() { handleFlags(flags) })
	assert.NotContains(s.T(), output, "unable")
	assert.NotContains(s.T(), output, "error")
	assert.Contains(s.T(), output, fixtureClientID)

	// Credentials that will not expire but will timeout during the warning period WILL be shown
	secret.CreatedAt = time.Now().Add(-82 * 24 * time.Hour)
	system.LastTokenAt = time.Now().Add(-54 * 24 * time.Hour)
	assert.Nil(s.T(), db.Save(&system).Error)
	assert.Nil(s.T(), db.Save(&secret).Error)
	output = captureOutput(func() { handleFlags(flags) })
	assert.NotContains(s.T(), output, "unable")
	assert.NotContains(s.T(), output, "error")
	assert.Contains(s.T(), output, fixtureClientID)

	// Credentials that will neither expire nor time out during the warning period will NOT be shown
	secret.CreatedAt = time.Now().Add(-82 * 24 * time.Hour)
	system.LastTokenAt = time.Now().Add(-52 * 24 * time.Hour)
	assert.Nil(s.T(), db.Save(&system).Error)
	assert.Nil(s.T(), db.Save(&secret).Error)
	output = captureOutput(func() { handleFlags(flags) })
	assert.NotContains(s.T(), output, "unable")
	assert.NotContains(s.T(), output, "error")
	assert.NotContains(s.T(), output, fixtureClientID)

	secret.CreatedAt = origCreatedAt
	system.LastTokenAt = origLastTokenAt
	assert.Nil(s.T(), db.Save(&system).Error)
	assert.Nil(s.T(), db.Save(&secret).Error)
}

func (s *MainTestSuite) TestCreateServers() {
	ps, as, forwarder := createServers()
	assert.NotNil(s.T(), ps)
	assert.NotNil(s.T(), as)
	assert.NotNil(s.T(), forwarder)
}

func TestMainTestSuite(t *testing.T) {
	suite.Run(t, new(MainTestSuite))
}

func captureOutput(f func()) string {
	var (
		buf     bytes.Buffer
		outOrig io.Writer
	)

	outOrig = output
	output = &buf
	f()
	output = outOrig
	return buf.String()
}

func captureLog(f func()) string {
	var (
		buf     bytes.Buffer
		origLog io.Writer
	)

	logger := ssas.GetLogger(ssas.Logger)
	origLog = logger.Out
	logger.SetOutput(&buf)

	f()
	logger.SetOutput(origLog)
	return buf.String()
}

package service

import (
	"context"
	"crypto/rsa"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type LoggingTestSuite struct {
	suite.Suite
	rr                *httptest.ResponseRecorder
	db                *gorm.DB
	server            *Server
	badSigningKeyPath string
	assertAud         string
}

func (t *LoggingTestSuite) SetupSuite() {
	t.db = ssas.Connection
	t.server = Server()
	t.badSigningKeyPath = "../../../shared_files/ssas/admin_test_signing_key.pem"
	t.assertAud = "http://local.testing.cms.gov/api/v2/Token/auth"
	StartBlacklist()
}

func (t *LoggingTestSuite) SetupClientAssertionTest() (ssas.Credentials, ssas.Group, *rsa.PrivateKey) {
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := t.db.Create(&group).Error
	require.Nil(t.T(), err)

	privateKey, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(t.T(), err)

	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(t.T(), err)

	si := ssas.SystemInput{
		ClientName: constants.TestSystemName,
		GroupID:    groupID,
		Scope:      ssas.DefaultScope,
		PublicKey:  pemString,
		IPs:        []string{},
		TrackingID: uuid.NewRandom().String(),
		XData:      `{"impl": "blah"}`,
	}
	creds, err := ssas.RegisterV2System(context.Background(), si)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), constants.TestSystemName, creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	return creds, group, privateKey
}

func (t *LoggingTestSuite) TestGetTransactionID() {
	creds, group, privateKey := t.SetupClientAssertionTest()

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, t.assertAud, time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), privateKey, creds.PublicKeyID)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))

}

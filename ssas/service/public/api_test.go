package public

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	m "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type APITestSuite struct {
	suite.Suite
	rr                *httptest.ResponseRecorder
	db                *gorm.DB
	server            *service.Server
	badSigningKeyPath string
	assertAud         string
}

func (s *APITestSuite) SetupSuite() {
	s.db = ssas.Connection
	s.server = Server()
	s.badSigningKeyPath = "../../../shared_files/ssas/admin_test_signing_key.pem"
	s.assertAud = "http://local.testing.cms.gov/api/v2/Token/auth"
	service.StartBlacklist()
}

func (s *APITestSuite) SetupTest() {
	s.db = ssas.Connection
	s.rr = httptest.NewRecorder()
}

func (s *APITestSuite) TearDownSuite() {
	ssas.Close(s.db)
}

func (s *APITestSuite) TestAuthRegisterEmpty() {
	regBody := strings.NewReader("")

	req, err := http.NewRequest("GET", "/auth/register", regBody)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, "T12123", []string{"T12123"})
	http.HandlerFunc(RegisterSystem).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, s.rr.Code)
}

func (s *APITestSuite) TestAuthRegisterBadJSON() {
	regBody := strings.NewReader("asdflkjghjkl")

	req, err := http.NewRequest("GET", "/auth/register", regBody)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, "T12123", []string{"T12123"})
	http.HandlerFunc(RegisterSystem).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, s.rr.Code)
}

func (s *APITestSuite) TestAuthRegisterSuccess() {
	groupID := "T12123"
	group := ssas.Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	regBody := strings.NewReader(fmt.Sprintf(`{"client_id":"my_client_id","client_name":"my_client_name","scope":"%s","jwks":{"keys":[{"e":"AAEAAQ","n":"ok6rvXu95337IxsDXrKzlIqw_I_zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I-EDgeFLLexr40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXHFq0XuUUgkX_TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP-yZFb8e0XSNTcQvXaQxAqmnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz-1NzHssDH_yk6UYFSszhDbWAzyqw","kty":"RSA"}]}}`,
		ssas.DefaultScope))

	req, err := http.NewRequest("GET", "/auth/register", regBody)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, "T12123", []string{"T12123"})
	http.HandlerFunc(RegisterSystem).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusCreated, s.rr.Code)

	var sys SystemResponse
	err = json.Unmarshal(s.rr.Body.Bytes(), &sys)
	assert.NoError(s.T(), err, s.rr.Body.String())
	assert.Equal(s.T(), "my_client_name", sys.ClientName)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthRegisterJSON() {
	groupID := "T12123"
	group := ssas.Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	regBody := strings.NewReader(fmt.Sprintf(`{"client_id":"my_client_id","client_name":"My\\Name\\Has\"Escaped Chars\"","scope":"%s","jwks":{"keys":[{"e":"AAEAAQ","n":"ok6rvXu95337IxsDXrKzlIqw_I_zPDG8JyEw2CTOtNMoDi1QzpXQVMGj2snNEmvNYaCTmFf51I-EDgeFLLexr40jzBXlg72quV4aw4yiNuxkigW0gMA92OmaT2jMRIdDZM8mVokoxyPfLub2YnXHFq0XuUUgkX_TlutVhgGbyPN0M12teYZtMYo2AUzIRggONhHvnibHP0CPWDjCwSfp3On1Recn4DPxbn3DuGslF2myalmCtkujNcrhHLhwYPP-yZFb8e0XSNTcQvXaQxAqmnWH6NXcOtaeWMQe43PNTAyNinhndgI8ozG3Hz-1NzHssDH_yk6UYFSszhDbWAzyqw","kty":"RSA"}]}}`,
		ssas.DefaultScope))

	req, err := http.NewRequest("GET", "/auth/register", regBody)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, "T12123", []string{"T12123"})
	http.HandlerFunc(RegisterSystem).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusCreated, s.rr.Code)

	assert.True(s.T(), json.Valid(s.rr.Body.Bytes()))
	var sys SystemResponse
	err = json.Unmarshal(s.rr.Body.Bytes(), &sys)
	assert.NoError(s.T(), err, s.rr.Body.String())
	assert.Equal(s.T(), `My\Name\Has"Escaped Chars"`, sys.ClientName)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthRegisterNoKey() {
	groupID := "T12123"
	group := ssas.Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	regBody := strings.NewReader(fmt.Sprintf(`{"client_id":"my_client_id","client_name":"my_client_name","scope":"%s"}`,
		ssas.DefaultScope))

	req, err := http.NewRequest("GET", "/auth/register", regBody)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, "T12123", []string{"T12123"})
	http.HandlerFunc(RegisterSystem).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusCreated, s.rr.Code)

	var sys SystemResponse
	err = json.Unmarshal(s.rr.Body.Bytes(), &sys)
	assert.NoError(s.T(), err, s.rr.Body.String())
	assert.Equal(s.T(), "my_client_name", sys.ClientName)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestResetSecretNoSystem() {
	groupID := "T23234"
	group := ssas.Group{GroupID: groupID}
	if err := s.db.Create(&group).Error; err != nil {
		s.FailNow("unable to create group: " + err.Error())
	}

	body := strings.NewReader(`{"client_id":"abcd1234"}`)
	req, err := http.NewRequest("PUT", "/reset", body)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, groupID, []string{groupID})
	http.HandlerFunc(ResetSecret).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, s.rr.Code)
	assert.Contains(s.T(), s.rr.Body.String(), "not found")

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestResetSecretEmpty() {
	groupID := "T23234"

	body := strings.NewReader("")
	req, err := http.NewRequest("PUT", "/reset", body)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, groupID, []string{groupID})
	http.HandlerFunc(ResetSecret).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, s.rr.Code)
}

func (s *APITestSuite) TestResetSecretBadJSON() {
	groupID := "T23234"

	body := strings.NewReader(`abcdefg`)
	req, err := http.NewRequest("PUT", "/reset", body)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, groupID, []string{groupID})
	http.HandlerFunc(ResetSecret).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, s.rr.Code)
}

func (s *APITestSuite) TestResetSecretSuccess() {
	groupID := "T23234"
	group := ssas.Group{GroupID: groupID}
	if err := s.db.Create(&group).Error; err != nil {
		s.FailNow("unable to create group: " + err.Error())
	}
	system := ssas.System{GID: group.ID, GroupID: group.GroupID, ClientID: "abcd1234"}
	if err := s.db.Create(&system).Error; err != nil {
		s.FailNow("unable to create system: " + err.Error())
	}

	hashedSecret := ssas.Hash("no_secret_at_all")
	secret := ssas.Secret{Hash: hashedSecret.String(), SystemID: system.ID}
	if err := s.db.Create(&secret).Error; err != nil {
		s.FailNow("unable to create secret: " + err.Error())
	}

	body := strings.NewReader(`{"client_id":"abcd1234"}`)
	req, err := http.NewRequest("PUT", "/reset", body)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, groupID, []string{groupID})
	http.HandlerFunc(ResetSecret).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)

	newSecret := ssas.Secret{}
	if err = s.db.Where("system_id = ?", system.ID).First(&newSecret).Error; err != nil {
		s.FailNow("unable to find secret: " + err.Error())
	}
	hash := ssas.Hash(newSecret.Hash)

	var sys SystemResponse
	err = json.Unmarshal(s.rr.Body.Bytes(), &sys)
	assert.NoError(s.T(), err, s.rr.Body.String())
	assert.True(s.T(), hash.IsHashOf(sys.ClientSecret))

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestResetSecretJSON() {
	groupID := "T23234"
	group := ssas.Group{GroupID: groupID}
	if err := s.db.Create(&group).Error; err != nil {
		s.FailNow("unable to create group: " + err.Error())
	}
	system := ssas.System{GID: group.ID, GroupID: group.GroupID, ClientID: "abcd1234", ClientName: `This\Name "has escaped chars`}
	if err := s.db.Create(&system).Error; err != nil {
		s.FailNow("unable to create system: " + err.Error())
	}

	hashedSecret := ssas.Hash("no_secret_at_all")
	secret := ssas.Secret{Hash: hashedSecret.String(), SystemID: system.ID}
	if err := s.db.Create(&secret).Error; err != nil {
		s.FailNow("unable to create secret: " + err.Error())
	}

	body := strings.NewReader(`{"client_id":"abcd1234"}`)
	req, err := http.NewRequest("PUT", "/reset", body)
	assert.Nil(s.T(), err)

	req = addRegDataContext(req, groupID, []string{groupID})
	http.HandlerFunc(ResetSecret).ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)

	newSecret := ssas.Secret{}
	if err = s.db.Where("system_id = ?", system.ID).First(&newSecret).Error; err != nil {
		s.FailNow("unable to find secret: " + err.Error())
	}
	hash := ssas.Hash(newSecret.Hash)

	var sys SystemResponse
	err = json.Unmarshal(s.rr.Body.Bytes(), &sys)
	assert.NoError(s.T(), err, s.rr.Body.String())
	assert.True(s.T(), hash.IsHashOf(sys.ClientSecret))
	assert.Equal(s.T(), `This\Name "has escaped chars`, sys.ClientName)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func addRegDataContext(req *http.Request, groupID string, groupIDs []string) *http.Request {
	rctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rd := ssas.AuthRegData{GroupID: groupID, AllowedGroupIDs: groupIDs}
	req = req.WithContext(context.WithValue(req.Context(), "rd", rd))
	return req
}

func (s *APITestSuite) TestTokenSuccess() {
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	_, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)

	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(s.T(), err)

	creds, err := ssas.RegisterSystem(constants.TestSystemName, groupID, ssas.DefaultScope, pemString, []string{}, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), constants.TestSystemName, creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	// now for the actual test
	req := httptest.NewRequest("POST", constants.TokenEndpoint, nil)
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	handler := http.HandlerFunc(token)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)
	t := TokenResponse{}
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&t))
	assert.NotEmpty(s.T(), t)
	assert.NotEmpty(s.T(), t.AccessToken)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestTokenErrAtGenerateTokenReturn401() {
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	_, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)

	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(s.T(), err)

	creds, err := ssas.RegisterSystem(constants.TestSystemName, groupID, ssas.DefaultScope, pemString, []string{}, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), constants.TestSystemName, creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	//setup mocks
	mock := &MockTokenCreator{}
	mock.On("GenerateToken", m.MatchedBy(func(req service.CommonClaims) bool { return true })).Return(&jwt.Token{Raw: ""}, "", errors.New("ERROR!"))
	SetMockAccessTokenCreator(s.T(), mock)

	//setup API request
	req := httptest.NewRequest("POST", constants.TokenEndpoint, nil)
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	req.Header.Add("Accept", constants.HeaderApplicationJSON)

	handler := http.HandlerFunc(token)

	//call
	handler.ServeHTTP(s.rr, req)

	//assert
	assert.Equal(s.T(), http.StatusUnauthorized, s.rr.Code)
	assert.Contains(s.T(), s.rr.Body.String(), "failure minting token")
	mock.AssertExpectations(s.T())

	//cleanup
	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestTokenEmptySecretProduces401() {
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	_, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)

	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(s.T(), err)

	creds, err := ssas.RegisterSystem(constants.TestSystemName, groupID, ssas.DefaultScope, pemString, []string{}, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), constants.TestSystemName, creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	req := httptest.NewRequest("POST", constants.TokenEndpoint, nil)
	req.SetBasicAuth(creds.ClientID, "")
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	handler := http.HandlerFunc(token)

	handler.ServeHTTP(s.rr, req)

	assert.Equal(s.T(), http.StatusUnauthorized, s.rr.Code)
	assert.Contains(s.T(), s.rr.Body.String(), "invalid client secret")
	assert.NotContains(s.T(), s.rr.Body.String(), "access_token")

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestTokenWrongSecretProduces401() {
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	_, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)

	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(s.T(), err)

	creds, err := ssas.RegisterSystem(constants.TestSystemName, groupID, ssas.DefaultScope, pemString, []string{}, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), constants.TestSystemName, creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	req := httptest.NewRequest("POST", constants.TokenEndpoint, nil)
	req.SetBasicAuth(creds.ClientID, "eogihfogihegoihego")
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	handler := http.HandlerFunc(token)

	handler.ServeHTTP(s.rr, req)

	assert.Equal(s.T(), http.StatusUnauthorized, s.rr.Code)
	assert.Contains(s.T(), s.rr.Body.String(), "invalid client secret")
	assert.NotContains(s.T(), s.rr.Body.String(), "access_token")

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestTokenEmptyClientIdProduces401() {
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	_, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)

	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(s.T(), err)

	creds, err := ssas.RegisterSystem(constants.TestSystemName, groupID, ssas.DefaultScope, pemString, []string{}, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), constants.TestSystemName, creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	req := httptest.NewRequest("POST", constants.TokenEndpoint, nil)
	req.SetBasicAuth("", creds.ClientSecret)
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	handler := http.HandlerFunc(token)

	handler.ServeHTTP(s.rr, req)

	assert.Equal(s.T(), http.StatusUnauthorized, s.rr.Code)
	assert.Contains(s.T(), s.rr.Body.String(), "invalid client id")

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) testIntrospectFlaw(flaw service.TokenFlaw, errorText string) {
	var (
		signingKeyPath string
		origLog        io.Writer
		buf            bytes.Buffer
	)

	origLog = ssas.Logger.Out
	ssas.Logger.SetOutput(&buf)
	defer func() {
		ssas.Logger.SetOutput(origLog)
	}()

	if flaw == service.BadSigner {
		signingKeyPath = s.badSigningKeyPath
	} else {
		signingKeyPath = os.Getenv("SSAS_PUBLIC_SIGNING_KEY_PATH")
	}

	creds, group := ssas.CreateTestXData(s.T(), s.db)

	system, err := ssas.GetSystemByClientID(creds.ClientID)
	assert.Nil(s.T(), err)
	data, err := ssas.XDataFor(system)
	assert.Nil(s.T(), err)

	claims := service.CommonClaims{
		TokenType: "AccessToken",
		SystemID:  fmt.Sprintf("%d", system.ID),
		ClientID:  creds.ClientID,
		Data:      data,
	}

	_, signedString, err := service.BadToken(&claims, flaw, signingKeyPath)
	assert.Nil(s.T(), err, fmt.Sprintf("Unable to create bad token for flaw %v", flaw))

	body := strings.NewReader(fmt.Sprintf(`{"token":"%s"}`, signedString))
	req := httptest.NewRequest("POST", "/introspect", body)
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	req.Header.Add("Content-Type", constants.HeaderApplicationJSON)
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	handler := http.HandlerFunc(introspect)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)

	var v map[string]bool
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&v))
	assert.NotEmpty(s.T(), v)
	assert.False(s.T(), v["active"], fmt.Sprintf("Unexpected success using bad token with flaw %v", flaw))
	assert.Regexpf(s.T(), regexp.MustCompile(errorText), buf.String(), fmt.Sprintf("Unable to find evidence of flaw %v in logs", flaw))
	assert.NoError(s.T(), ssas.CleanDatabase(group))
}

func (s *APITestSuite) TestIntrospectFailure() {
	flaws := map[service.TokenFlaw]string{
		service.Postdated:        "token used before issued",
		service.ExtremelyExpired: "token is expired",
		service.BadSigner:        "crypto/rsa: verification error",
		service.Expired:          "token is expired",
		service.BadIssuer:        "missing one or more claims",
		service.MissingID:        "missing one or more claims",
	}
	for flaw, errorText := range flaws {
		s.testIntrospectFlaw(flaw, errorText)
	}
}

func (s *APITestSuite) TestIntrospectSuccess() {
	creds, group := ssas.CreateTestXData(s.T(), s.db)

	req := httptest.NewRequest("POST", constants.TokenEndpoint, nil)
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	handler := http.HandlerFunc(token)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)
	t := TokenResponse{}
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&t))
	assert.NotEmpty(s.T(), t)
	assert.NotEmpty(s.T(), t.AccessToken)

	// the actual test
	body := strings.NewReader(fmt.Sprintf(`{"token":"%s"}`, t.AccessToken))
	req = httptest.NewRequest("POST", "/introspect", body)
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	req.Header.Add("Content-Type", constants.HeaderApplicationJSON)
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	handler = http.HandlerFunc(introspect)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)

	var v map[string]bool
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&v))
	assert.NotEmpty(s.T(), v)
	assert.True(s.T(), v["active"])

	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestSaveTokenTime() {
	groupID := ssas.RandomHexID()[0:4]

	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	creds, err := ssas.RegisterSystem("Introspect Test", groupID, ssas.DefaultScope, "", []string{}, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), "Introspect Test", creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	system, err := ssas.GetSystemByClientID(creds.ClientID)
	assert.Nil(s.T(), err)
	assert.True(s.T(), system.LastTokenAt.IsZero())

	system.SaveTokenTime()
	system, err = ssas.GetSystemByClientID(creds.ClientID)
	assert.Nil(s.T(), err)
	assert.False(s.T(), system.LastTokenAt.IsZero())

	time1 := system.LastTokenAt
	system.SaveTokenTime()
	system, err = ssas.GetSystemByClientID(creds.ClientID)
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), system.LastTokenAt, time1)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestJSONError() {
	rr := httptest.NewRecorder()
	service.JSONError(rr, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "unauthorized")

	b, _ := ioutil.ReadAll(rr.Body)
	var error ssas.ErrorResponse
	_ = json.Unmarshal(b, &error)

	assert.Equal(s.T(), "Unauthorized", error.Error)
	assert.Equal(s.T(), "unauthorized", error.ErrorDescription)
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

func (s *APITestSuite) SetupClientAssertionTest() (ssas.Credentials, ssas.Group, *rsa.PrivateKey) {
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	privateKey, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)

	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(s.T(), err)

	si := ssas.SystemInput{
		ClientName: constants.TestSystemName,
		GroupID:    groupID,
		Scope:      ssas.DefaultScope,
		PublicKey:  pemString,
		IPs:        []string{},
		TrackingID: uuid.NewRandom().String(),
		XData:      `{"impl": "blah"}`,
	}
	creds, err := ssas.RegisterV2System(si)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), constants.TestSystemName, creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	return creds, group, privateKey
}

// Authenticate and generate access token using JWT (v2/token/)
func (s *APITestSuite) TestAuthenticatingWithJWT() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)
	t := TokenResponse{}
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&t))
	assert.NotEmpty(s.T(), t)
	assert.NotEmpty(s.T(), t.AccessToken)
	assert.NotEmpty(s.T(), t.Scope)
	assert.Equal(s.T(), "system/*.*", t.Scope)

	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

// Authenticate and generate access token using JWT (v2/token/)
func (s *APITestSuite) TestAuthenticatingWithJWTUsingSecondPublicKey() {
	creds, group, _ := s.SetupClientAssertionTest()
	system, _ := ssas.GetSystemByID(creds.SystemID)
	pubK, sig, newPrivateKey, _ := ssas.GeneratePublicKey(2048)
	secondKey, _ := system.AddAdditionalPublicKey(strings.NewReader(pubK), sig)

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), newPrivateKey, secondKey.UUID)
	assert.Nil(s.T(), errors)

	form := buildClientAssertionForm(clientAssertion)
	req := buildClientAssertionRequest(form)

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)
	t := TokenResponse{}
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&t))
	assert.NotEmpty(s.T(), t)
	assert.NotEmpty(s.T(), t.AccessToken)
	assert.NotEmpty(s.T(), t.Scope)
	assert.Equal(s.T(), "system/*.*", t.Scope)

	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTUsingWrongPrivateKey() {
	creds, group, firstPrivateKey := s.SetupClientAssertionTest()
	system, _ := ssas.GetSystemByID(creds.SystemID)
	pubK, sig, _, _ := ssas.GeneratePublicKey(2048)
	secondKey, _ := system.AddAdditionalPublicKey(strings.NewReader(pubK), sig)

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), firstPrivateKey, secondKey.UUID)
	assert.Nil(s.T(), errors)

	form := buildClientAssertionForm(clientAssertion)
	req := buildClientAssertionRequest(form)

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "crypto/rsa: verification error")
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithMismatchLocation() {
	os.Setenv("SSAS_MACAROON_LOCATION", "localpost")
	creds, group, privateKey := s.SetupClientAssertionTest()
	os.Unsetenv("SSAS_MACAROON_LOCATION")

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, s.rr.Code)
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithExpBeforeIssuedTime() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	expiresAt := time.Now().Unix() + 200
	issuedAt := expiresAt + 1
	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, issuedAt, expiresAt, privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "token used before issued")
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithMoreThan5MinutesExpTime() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	issuedAt := time.Now().Unix()
	expiresAt := issuedAt + 350

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, issuedAt, expiresAt, privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "IssuedAt (iat) and ExpiresAt (exp) claims are more than 5 minutes apart")
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithExpiredToken() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	issuedAt := time.Now().Unix() - 3600 //simulate token issued an hour ago.
	expiresAt := issuedAt + 200          //exp within 5 min of iat time

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, issuedAt, expiresAt, privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "token is expired")
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTSignedWithWrongKey() {
	creds, group, _ := s.SetupClientAssertionTest() //Correct private key is created and uploaded here
	issuedAt := time.Now().Unix()
	expiresAt := issuedAt + 200

	wrongPrivateKey, _, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, issuedAt, expiresAt, wrongPrivateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "crypto/rsa: verification error")
	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithSoftDeletedPublicKey() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	issuedAt := time.Now().Unix()
	expiresAt := issuedAt + 200

	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, s.assertAud, issuedAt, expiresAt, privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	system, err := ssas.GetSystemByID(creds.SystemID)
	assert.Nil(s.T(), err)
	key, err := system.GetEncryptionKey(uuid.NewRandom().String())
	assert.Nil(s.T(), err)

	//Soft delete public key
	db := ssas.Connection
	assert.Nil(s.T(), s.db.Delete(&key).Error)

	//Ensure record was soft deleted, and not permanently deleted.
	key, err = system.GetEncryptionKey(uuid.NewRandom().String())
	assert.NotNil(s.T(), err)
	assert.Empty(s.T(), key)
	var encryptionKey ssas.EncryptionKey
	err = db.Unscoped().First(&encryptionKey, "system_id = ?", creds.SystemID).Error
	assert.Nil(s.T(), err)
	assert.NotEmpty(s.T(), encryptionKey)

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "key not found for system: "+creds.ClientToken)
	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithMissingIssuerClaim() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	_, clientAssertion, errors := mintClientAssertion("", creds.SystemID, s.assertAud, time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "missing issuer (iss) in jwt claims")
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithBadAudienceClaim() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, creds.ClientToken, "https://invalid.url.com", time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", clientAssertion)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "invalid audience (aud) claim")
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithMissingKID() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	claims := service.CommonClaims{}

	token := jwt.New(jwt.SigningMethodRS512)
	claims.TokenType = "ClientAssertion"
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Minute * 5).Unix()
	claims.Subject = creds.ClientToken
	claims.Issuer = creds.ClientToken
	claims.Audience = s.assertAud
	token.Claims = claims
	var signedString, err = token.SignedString(privateKey)
	assert.Nil(s.T(), err)

	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", signedString)

	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "missing public key id (kid) in jwt header")
	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithMissingJTI() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	claims := service.CommonClaims{}

	token := jwt.New(jwt.SigningMethodRS512)
	claims.TokenType = "ClientAssertion"
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(time.Minute * 5).Unix()
	claims.Subject = creds.ClientToken
	claims.Issuer = creds.ClientToken
	claims.Audience = s.assertAud
	token.Header["kid"] = creds.PublicKeyID
	token.Claims = claims
	var signedString, err = token.SignedString(privateKey)
	assert.Nil(s.T(), err)

	form := buildClientAssertionForm(signedString)
	req := buildClientAssertionRequest(form)

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "missing Token ID (jti) claim")
	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestAuthenticatingWithJWTWithMissingSubjectClaim() {
	creds, group, privateKey := s.SetupClientAssertionTest()
	_, clientAssertion, errors := mintClientAssertion(creds.ClientToken, "", s.assertAud, time.Now().Unix(), time.Now().Add(time.Minute*5).Unix(), privateKey, creds.PublicKeyID)
	assert.Nil(s.T(), errors)

	form := buildClientAssertionForm(clientAssertion)
	req := buildClientAssertionRequest(form)

	handler := http.HandlerFunc(tokenV2)
	handler.ServeHTTP(s.rr, req)

	s.verifyErrorResponse(http.StatusBadRequest, "subject (sub) and issuer (iss) claims do not match")
	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func buildClientAssertionRequest(form url.Values) *http.Request {
	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func buildClientAssertionForm(assertion string) url.Values {
	form := url.Values{}
	form.Add("scope", "system/*.*")
	form.Add("grant_type", "client_credentials")
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", assertion)
	return form
}

func (s *APITestSuite) TestClientAssertionAuthWithBadScopeParam() {
	//System does not need to be created for this test since header and param checks are done before assertion is parsed/looked up.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", "value_does_not_matter_for_this_test")
	handler := http.HandlerFunc(tokenV2)

	//Invalid scope value
	form.Set("scope", "system/invalid")
	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", constants.HeaderApplicationJSON)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(s.rr, req)
	s.verifyErrorResponse(http.StatusBadRequest, "invalid scope value")
}

func (s *APITestSuite) TestClientAssertionAuthWithBadAcceptHeader() {
	//System does not need to be created for this test since header and param checks are done before assertion is parsed/looked up.
	form := buildClientAssertionForm("value_does_not_matter_for_this_test")
	handler := http.HandlerFunc(tokenV2)

	//Invalid accept header value
	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/txt")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(s.rr, req)
	s.verifyErrorResponse(http.StatusBadRequest, "invalid Accept header value. Supported types: [application/json]")
}

func (s *APITestSuite) TestClientAssertionAuthWithBadContentTypeHeader() {
	//System does not need to be created for this test since header and param checks are done before assertion is parsed/looked up.
	form := buildClientAssertionForm("value_does_not_matter_for_this_test")
	handler := http.HandlerFunc(tokenV2)

	//Missing Content-Type header
	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", constants.HeaderApplicationJSON)
	handler.ServeHTTP(s.rr, req)
	s.verifyErrorResponse(http.StatusBadRequest, "missing Content-Type header")

	//Invalid Content-Type header value
	req = httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", constants.HeaderApplicationJSON)
	req.Header.Set("Content-Type", "application/bad-type")
	handler.ServeHTTP(s.rr, req)
	s.verifyErrorResponse(http.StatusBadRequest, "invalid Content Type Header value. Supported Types: [application/x-www-form-urlencoded]")
}

func (s *APITestSuite) TestClientAssertionAuthWithBadGrantTypeParam() {
	//System does not need to be created for this test since header and param checks are done before assertion is parsed/looked up.
	form := buildClientAssertionForm("value_does_not_matter_for_this_test")
	form.Set("grant_type", "invalid_grant_type")
	handler := http.HandlerFunc(tokenV2)

	//Invalid grant_type param
	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(s.rr, req)
	s.verifyErrorResponse(http.StatusBadRequest, "invalid value for grant_type")
}

func (s *APITestSuite) TestClientAssertionAuthWithBadClientAssertionTypeParam() {
	//System does not need to be created for this test since header and param checks are done before assertion is parsed/looked up.
	form := buildClientAssertionForm("value_does_not_matter_for_this_test")
	handler := http.HandlerFunc(tokenV2)

	//Invalid client_assertion_type param
	form.Set("client_assertion_type", "invalid_client_assertion_type")
	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Add("Accept", constants.HeaderApplicationJSON)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(s.rr, req)
	s.verifyErrorResponse(http.StatusBadRequest, "invalid value for client_assertion_type")
}

func (s *APITestSuite) TestClientAssertionAuthWithMissingClientAssertionParam() {
	//Create system and valid client assertion token
	form := buildClientAssertionForm("value_does_not_matter_for_this_test")
	form.Del("client_assertion")
	handler := http.HandlerFunc(tokenV2)

	//Missing client_assertion param
	req := httptest.NewRequest("POST", "/v2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Accept", constants.HeaderApplicationJSON)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler.ServeHTTP(s.rr, req)
	s.verifyErrorResponse(http.StatusBadRequest, "missing client_assertion")
}

func (s *APITestSuite) verifyErrorResponse(expectedStatus interface{}, expectedMsg string) {
	assert.Equal(s.T(), expectedStatus, s.rr.Code)
	t := ssas.ErrorResponse{}
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&t))
	assert.NotEmpty(s.T(), t)
	assert.Regexp(s.T(), regexp.MustCompile(regexp.QuoteMeta(expectedMsg)), t.Error)
}

func mintClientAssertion(issuer, subject, aud string, issuedAt, expiresAt int64, privateKey *rsa.PrivateKey, kid string) (*jwt.Token, string, error) {
	claims := service.CommonClaims{}

	token := jwt.New(jwt.SigningMethodRS512)
	tokenID := uuid.NewRandom().String()
	claims.IssuedAt = issuedAt
	claims.ExpiresAt = expiresAt
	claims.Id = tokenID
	claims.Subject = subject
	claims.Issuer = issuer
	claims.Audience = aud
	token.Claims = claims
	token.Header["kid"] = kid
	var signedString, err = token.SignedString(privateKey)
	if err != nil {
		ssas.TokenMintingFailure(ssas.Event{TokenID: tokenID})
		ssas.Logger.Errorf("token signing error %s", err)
		return nil, "", err
	}
	return token, signedString, nil
}

func (s *APITestSuite) TestGetTokenInfo() {
	_, access, err := s.MintTestAccessToken()
	assert.NoError(s.T(), err)

	body := fmt.Sprintf("{\"token\":\"%s\"}", access)

	req := httptest.NewRequest("POST", "/token_info", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	handler := http.HandlerFunc(validateAndParseToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json; charset=utf-8", rr.Result().Header.Get("Content-Type"))
	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.NotEmpty(s.T(), result["data"])
	assert.NotEmpty(s.T(), result["system_data"])
	assert.Equal(s.T(), `{"impl": "2"}`, result["system_data"])
	assert.NotEmpty(s.T(), result["scope"])
}

func (s *APITestSuite) TestGetTokenInfoWithMissingToken() {
	body := "{}"
	req := httptest.NewRequest("POST", "/token_info", strings.NewReader(body))
	rCtx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rCtx))
	handler := http.HandlerFunc(validateAndParseToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusUnauthorized, rr.Result().StatusCode)

	var resMap map[string]string
	err := json.NewDecoder(rr.Body).Decode(&resMap)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "missing \"token\" field in body", resMap["error_description"])
}

func (s *APITestSuite) TestGetTokenInfoWithEmptyToken() {
	body := `{"token":""}`
	req := httptest.NewRequest("POST", "/token_info", strings.NewReader(body))
	rCtx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rCtx))
	handler := http.HandlerFunc(validateAndParseToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusUnauthorized, rr.Result().StatusCode)

	var resMap map[string]string
	err := json.NewDecoder(rr.Body).Decode(&resMap)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "missing \"token\" field in body", resMap["error_description"])
}

func (s *APITestSuite) TestGetTokenInfoWithCorruptToken() {
	body := `{"token":"dafdasfdsfadfdasfdsafadsfadsf"}`

	req := httptest.NewRequest("POST", "/token_info", strings.NewReader(body))
	rCtx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rCtx))
	handler := http.HandlerFunc(validateAndParseToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Contains(s.T(), rr.Body.String(), `{"valid":false}`)
}

func (s *APITestSuite) TestGetTokenInfoWithExpiredToken() {
	_, access, err := s.MintTestAccessTokenWithDuration(time.Second * 1)
	assert.NoError(s.T(), err)
	time.Sleep(5 * time.Second)

	body := fmt.Sprintf("{\"token\":\"%s\"}", access)
	req := httptest.NewRequest("POST", "/token_info", strings.NewReader(body))
	rCtx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rCtx))
	handler := http.HandlerFunc(validateAndParseToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Contains(s.T(), rr.Body.String(), `{"valid":false}`)
}

func (s *APITestSuite) MintTestAccessTokenWithDuration(duration time.Duration) (*jwt.Token, string, error) {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)
	system, err := ssas.GetSystemByClientID(creds.ClientID)
	assert.Nil(s.T(), err)
	data, err := ssas.XDataFor(system)
	assert.Nil(s.T(), err)

	claims := service.CommonClaims{
		TokenType:   "AccessToken",
		SystemID:    fmt.Sprintf("%d", system.ID),
		ClientID:    creds.ClientID,
		Data:        data,
		SystemXData: system.XData,
	}
	return s.server.MintTokenWithDuration(&claims, duration)
}

func (s *APITestSuite) MintTestAccessToken() (*jwt.Token, string, error) {
	return s.MintTestAccessTokenWithDuration(time.Minute * 10)
}

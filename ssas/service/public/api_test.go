package public

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/require"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"

	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type APITestSuite struct {
	suite.Suite
	rr *httptest.ResponseRecorder
	db *gorm.DB
}

func (s *APITestSuite) SetupSuite() {
	ssas.InitializeSystemModels()
	s.db = ssas.GetGORMDbConnection()
	_ = Server()
	service.StartBlacklist()
}

func (s *APITestSuite) SetupTest() {
	s.db = ssas.GetGORMDbConnection()
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

	j := map[string]string{}
	err = json.Unmarshal(s.rr.Body.Bytes(), &j)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), "my_client_name", j["client_name"])

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
	system := ssas.System{GroupID: group.GroupID, ClientID: "abcd1234"}
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

	j := map[string]string{}
	err = json.Unmarshal(s.rr.Body.Bytes(), &j)
	assert.Nil(s.T(), err)
	assert.True(s.T(), hash.IsHashOf(j["client_secret"]))

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

	creds, err := ssas.RegisterSystem("Token Test", groupID, ssas.DefaultScope, pemString, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), "Token Test", creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	// now for the actual test
	req := httptest.NewRequest("POST", "/token", nil)
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	req.Header.Add("Accept", "application/json")
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

func (s *APITestSuite) TestIntrospectSuccess() {
	groupID := ssas.RandomHexID()[0:4]

	group := ssas.Group{GroupID: groupID, XData: "x_data"}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err)

	_, pubKey, err := ssas.GenerateTestKeys(2048)
	require.Nil(s.T(), err)
	pemString, err := ssas.ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(s.T(), err)

	creds, err := ssas.RegisterSystem("Introspect Test", groupID, ssas.DefaultScope, pemString, uuid.NewRandom().String())
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), "Introspect Test", creds.ClientName)
	assert.NotNil(s.T(), creds.ClientSecret)

	req := httptest.NewRequest("POST", "/token", nil)
	req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	req.Header.Add("Accept", "application/json")
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
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	handler = http.HandlerFunc(introspect)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)

	var v map[string]bool
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&v))
	assert.NotEmpty(s.T(), v)
	assert.True(s.T(), v["active"])

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

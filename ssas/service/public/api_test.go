package public

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi"
	"github.com/pborman/uuid"

	"gorm.io/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type APITestSuite struct {
	suite.Suite
	rr                *httptest.ResponseRecorder
	db                *gorm.DB
	server            *service.Server
	badSigningKeyPath string
}

func (s *APITestSuite) SetupSuite() {
	s.db = ssas.GetGORMDbConnection()
	s.server = Server()
	s.badSigningKeyPath = "../../../shared_files/ssas/admin_test_signing_key.pem"
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

	creds, err := ssas.RegisterSystem("Token Test", groupID, ssas.DefaultScope, pemString, []string{}, uuid.NewRandom().String())
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
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	handler := http.HandlerFunc(introspect)
	handler.ServeHTTP(s.rr, req)
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)

	var v map[string]bool
	assert.NoError(s.T(), json.NewDecoder(s.rr.Body).Decode(&v))
	assert.NotEmpty(s.T(), v)
	assert.False(s.T(), v["active"], fmt.Sprintf("Unexpected success using bad token with flaw %v", flaw))
	assert.Contains(s.T(), buf.String(), errorText, fmt.Sprintf("Unable to find evidence of flaw %v in logs", flaw))
	assert.NoError(s.T(), ssas.CleanDatabase(group))
}

func (s *APITestSuite) TestIntrospectFailure() {
	flaws := map[service.TokenFlaw]string{
		service.Postdated:        "token used before issued",
		service.ExtremelyExpired: "Token is expired",
		service.BadSigner:        "crypto/rsa: verification error",
		service.Expired:          "Token is expired",
		service.BadIssuer:        "missing one or more claims",
		service.MissingID:        "missing one or more claims",
	}
	for flaw, errorText := range flaws {
		s.testIntrospectFlaw(flaw, errorText)
	}
}

func (s *APITestSuite) TestIntrospectSuccess() {
	creds, group := ssas.CreateTestXData(s.T(), s.db)

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

func (s *APITestSuite) TestJsonError() {
	w := httptest.NewRecorder()
	jsonError(w, http.StatusText(http.StatusUnauthorized), "unauthorized")
	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(s.T(), err)
	assert.True(s.T(), json.Valid(body))
	assert.Equal(s.T(), `{"error":"Unauthorized","error_description":"unauthorized"}`, string(body))
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

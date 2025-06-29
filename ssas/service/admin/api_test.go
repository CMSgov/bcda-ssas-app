package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

const SampleGroup string = `{
  "group_id":"%s",
  "name": "ACO Corp Systems",
  "resources": [
    {
      "id": "xxx",
      "name": "BCDA API",
      "scopes": [
        "bcda-api"
      ]
    },
    {
      "id": "eft",
      "name": "EFT CCLF",
      "scopes": [
        "eft-app:download",
        "eft-data:read"
      ]
    }
  ],
  "scopes": [
    "user-admin",
    "system-admin"
  ],
  "users": [
    "00uiqolo7fEFSfif70h7",
    "l0vckYyfyow4TZ0zOKek",
    "HqtEi2khroEZkH4sdIzj"
  ],
  "xdata": %s
}`
const V2_SYSTEM_ROUTE = "/v2/system/"
const SampleXdata string = `"{\"cms_ids\":[\"T67890\",\"T54321\"]}"`

type APITestSuite struct {
	suite.Suite
	db       *gorm.DB
	logEntry *ssas.APILoggerEntry
}

func (s *APITestSuite) SetupSuite() {
	s.db = ssas.Connection
	service.StartBlacklist()
	ssas.MaxIPs = 3
	s.logEntry = MakeTestStructuredLoggerEntry(logrus.Fields{"cms_id": "A9999", "request_id": uuid.NewUUID().String()})
}

func (s *APITestSuite) TearDownSuite() {
	//ssas.Close(s.db)
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

func (s *APITestSuite) TestCreateGroup() {

	gid := ssas.RandomBase64(16)
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)

	req := httptest.NewRequest("POST", "/group", strings.NewReader(testInput))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))

	logger := ssas.GetLogger(ssas.Logger)
	logHook := test.NewLocal(logger)

	handler := http.Handler(service.GetTransactionID(service.NewCtxLogger(http.HandlerFunc(createGroup))))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	entries := logHook.AllEntries()

	assert.Contains(s.T(), entries[0].Data, "Op")
	assert.Contains(s.T(), entries[0].Data, "transaction_id")

	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	g := ssas.Group{}
	if errors.Is(s.db.First(&g, "group_id = ?", gid).Error, gorm.ErrRecordNotFound) {
		assert.FailNow(s.T(), fmt.Sprintf("record not found for group_id=%s", gid))
	}

	// Duplicate request fails
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)

	err := ssas.CleanDatabase(g)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateGroupFailure() {
	gid := ssas.RandomBase64(16)
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)
	req := httptest.NewRequest("POST", "/group", strings.NewReader(testInput))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	g := ssas.Group{}
	if errors.Is(s.db.First(&g, "group_id = ?", gid).Error, gorm.ErrRecordNotFound) {
		assert.FailNow(s.T(), fmt.Sprintf("record not found for group_id=%s", gid))
	}
	err := ssas.CleanDatabase(g)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateGroupEmptyGroupId() {
	gid := ""
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)
	req := httptest.NewRequest("POST", "/group", strings.NewReader(testInput))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestListGroups() {
	g1ID := ssas.RandomBase64(16)
	g2ID := ssas.RandomHexID()

	testInput1 := fmt.Sprintf(SampleGroup, g1ID, SampleXdata)
	gd := ssas.GroupData{}
	err := json.Unmarshal([]byte(testInput1), &gd)
	assert.Nil(s.T(), err)
	g1, err := ssas.CreateGroup(context.Background(), gd)
	assert.Nil(s.T(), err)

	gd.GroupID = g2ID
	gd.Name = "another-fake-name"
	g2, err := ssas.CreateGroup(context.Background(), gd)
	assert.Nil(s.T(), err)

	req := httptest.NewRequest("GET", "/group", nil)
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(listGroups)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	groupList := ssas.GroupList{}
	err = json.Unmarshal(rr.Body.Bytes(), &groupList)
	assert.Nil(s.T(), err)

	found1 := false
	found2 := false
	for _, g := range groupList.Groups {
		switch g.GroupID {
		case g1ID:
			found1 = true
		case g2ID:
			found2 = true
		default: //NOOP
		}
	}
	assert.True(s.T(), found1, "group 1 not present in list")
	assert.True(s.T(), found2, "group 2 not present in list")

	err = ssas.CleanDatabase(g1)
	assert.Nil(s.T(), err)
	err = ssas.CleanDatabase(g2)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestUpdateGroup() {
	gid := ssas.RandomBase64(16)
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)
	gd := ssas.GroupData{}
	err := json.Unmarshal([]byte(testInput), &gd)
	assert.Nil(s.T(), err)
	g, err := ssas.CreateGroup(context.Background(), gd)
	assert.Nil(s.T(), err)

	url := fmt.Sprintf("/group/%v", g.ID)
	req := httptest.NewRequest("PUT", url, strings.NewReader(testInput))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(g.ID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(updateGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	err = ssas.CleanDatabase(g)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestUpdateGroupBadGroupID() {
	gid := ssas.RandomBase64(16)
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)
	gd := ssas.GroupData{}
	err := json.Unmarshal([]byte(testInput), &gd)
	assert.Nil(s.T(), err)

	// No group exists
	url := fmt.Sprintf("/group/%v", gid)
	req := httptest.NewRequest("PUT", url, strings.NewReader(testInput))
	rctx := chi.NewRouteContext()
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(updateGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestRevokeToken() {
	tokenID := "abc-123-def-456"

	url := fmt.Sprintf("/token/%s", tokenID)
	req := httptest.NewRequest("DELETE", url, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tokenID", tokenID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(revokeToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)

	assert.True(s.T(), service.TokenBlacklist.IsTokenBlacklisted(tokenID))
	assert.False(s.T(), service.TokenBlacklist.IsTokenBlacklisted("this_key_should_not_exist"))
}

func (s *APITestSuite) TestRevokeTokenNoToken() {
	tokenID := ""

	url := fmt.Sprintf("/token/%s", tokenID)
	req := httptest.NewRequest("DELETE", url, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tokenID", tokenID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(revokeToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// TODO(BCDA-7212): Handle gracefully
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestDeleteGroup() {
	gid := ssas.RandomHexID()
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)
	groupBytes := []byte(testInput)
	gd := ssas.GroupData{}
	err := json.Unmarshal(groupBytes, &gd)
	assert.Nil(s.T(), err)
	g, err := ssas.CreateGroup(context.Background(), gd)
	assert.Nil(s.T(), err)

	url := fmt.Sprintf("/group/%v", g.ID)
	req := httptest.NewRequest("DELETE", url, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(g.ID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(deleteGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.True(s.T(), errors.Is(s.db.First(&ssas.Group{}, g.ID).Error, gorm.ErrRecordNotFound))
	err = ssas.CleanDatabase(g)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateSystem() {
	logger := ssas.GetLogger(ssas.Logger)
	logHook := test.NewLocal(logger)
	group := ssas.Group{GroupID: "test-group-id", XData: string(`{"cms_ids":["A9999"]}`)}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhxobShmNifzW3xznB+L\nI8+hgaePpSGIFCtFz2IXGU6EMLdeufhADaGPLft9xjwdN1ts276iXQiaChKPA2CK\n/CBpuKcnU3LhU8JEi7u/db7J4lJlh6evjdKVKlMuhPcljnIKAiGcWln3zwYrFCeL\ncN0aTOt4xnQpm8OqHawJ18y0WhsWT+hf1DeBDWvdfRuAPlfuVtl3KkrNYn1yqCgQ\nlT6v/WyzptJhSR1jxdR7XLOhDGTZUzlHXh2bM7sav2n1+sLsuCkzTJqWZ8K7k7cI\nXK354CNpCdyRYUAUvr4rORIAUmcIFjaR3J4y/Dh2JIyDToOHg7vjpCtNnNoS+ON2\nHwIDAQAB\n-----END PUBLIC KEY-----", "tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.Handler(service.NewCtxLogger(http.HandlerFunc(createSystem)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.NotEmpty(s.T(), result["client_id"])
	assert.NotEmpty(s.T(), result["client_secret"])
	assert.Empty(s.T(), result["client_token"])
	assert.Equal(s.T(), "Test Client", result["client_name"])

	logs := logHook.AllEntries()
	alertLog := false
	for _, v := range logs {
		if strings.Contains(v.Message, "A9999") {
			alertLog = true
		}
	}

	// verify the logging used for aco alerts
	assert.True(s.T(), alertLog)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateSystemMultipleIps() {
	randomIPv4 := ssas.RandomIPv4()
	randomIPv6 := ssas.RandomIPv6()
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	reqBody := fmt.Sprintf(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "ips": ["%s", "%s"],"tracking_id": "T00000"}`, randomIPv4, randomIPv6)
	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader(reqBody))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))

	creds := ssas.Credentials{}
	err = json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&creds)
	assert.Nil(s.T(), err)
	assert.NotEmpty(s.T(), creds)
	assert.NotEqual(s.T(), "", creds.ClientID)
	assert.Equal(s.T(), "Test Client", creds.ClientName)

	system, err := ssas.GetSystemByClientID(context.Background(), creds.ClientID)
	assert.Nil(s.T(), err)
	ips, err := system.GetIPs()
	assert.Nil(s.T(), err)
	assert.True(s.T(), contains(ips, randomIPv4))
	assert.True(s.T(), contains(ips, randomIPv6))

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateSystemBadIp() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", ips: ["304.0.2.1/32"],"tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateSystemEmptyKey() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "public_key": "", "tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.NotEmpty(s.T(), result["client_id"])
	assert.NotEmpty(s.T(), result["client_secret"])
	assert.Equal(s.T(), "Test Client", result["client_name"])

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateSystemNoKey() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.NotEmpty(s.T(), result["client_id"])
	assert.NotEmpty(s.T(), result["client_secret"])
	assert.Equal(s.T(), "Test Client", result["client_name"])

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateSystemInvalidRequest() {
	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader("{ badJSON }"))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreateSystemMissingRequiredParam() {
	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader(`{"group_id": "T00001", "client_name": "Test Client 1", "scope": "bcda-api"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestResetCredentials() {
	logger := ssas.GetLogger(ssas.Logger)
	logHook := test.NewLocal(logger)

	group := ssas.Group{GroupID: "test-reset-creds-group", XData: string(`{"cms_ids":["A9999"]}`)}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)
	secret := ssas.Secret{Hash: "test-reset-creds-hash", SystemID: system.ID}
	s.db.Create(&secret)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("PUT", "/system/"+systemID+"/credentials", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)

	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry.Logger))
	handler := http.Handler(service.NewCtxLogger(http.HandlerFunc(resetCredentials)))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	newSecret := result["client_secret"]
	assert.NotEmpty(s.T(), newSecret)
	assert.NotEqual(s.T(), secret.Hash, newSecret)

	logs := logHook.AllEntries()
	alertLog := false
	for _, v := range logs {
		if strings.Contains(v.Message, "A9999") {
			alertLog = true
		}
	}

	// verify the logging used for aco alerts
	assert.True(s.T(), alertLog)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestResetCredentialsInvalidSystemID() {
	systemID := "999"
	req := httptest.NewRequest("PUT", "/system/"+systemID+"/credentials", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(resetCredentials)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestGetPublicKeyBadSystemID() {
	systemID := strconv.FormatUint(uint64(9999), 10)
	req := httptest.NewRequest("GET", "/system/"+systemID+"/key", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getPublicKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestGetPublicKey() {
	group := ssas.Group{GroupID: "api-test-get-public-key-group"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := ssas.System{GID: group.ID, ClientID: "api-test-get-public-key-client"}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	key1Str := "publickey1"
	encrKey1 := ssas.EncryptionKey{
		SystemID: system.ID,
		Body:     key1Str,
	}
	err = s.db.Create(&encrKey1).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("GET", "/system/"+systemID+"/key", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getPublicKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &result)
	if err != nil {
		s.FailNow(err.Error())
	}

	assert.Equal(s.T(), system.ClientID, result["client_id"])
	resPublicKey := result["public_key"]
	assert.NotEmpty(s.T(), resPublicKey)
	assert.Equal(s.T(), key1Str, resPublicKey)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestGetPublicKeyRotation() {
	group := ssas.Group{GroupID: "api-test-get-public-key-group"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := ssas.System{GID: group.ID, ClientID: "api-test-get-public-key-client"}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	key1, _, _, _ := ssas.GeneratePublicKey(2048)
	rk1, err := system.SavePublicKey(strings.NewReader(key1), "")
	if err != nil {
		s.FailNow(err.Error())
	}

	key2, _, _, _ := ssas.GeneratePublicKey(2048)
	rk2, err := system.SavePublicKey(strings.NewReader(key2), "")
	if err != nil {
		s.FailNow(err.Error())
	}

	assert.NotEqual(s.T(), rk1.UUID, rk2.UUID)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("GET", "/system/"+systemID+"/key", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getPublicKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &result)
	if err != nil {
		s.FailNow(err.Error())
	}

	assert.Equal(s.T(), system.ClientID, result["client_id"])
	resPublicKey := result["public_key"]
	assert.NotEmpty(s.T(), resPublicKey)
	assert.Equal(s.T(), key2, resPublicKey)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestDeactivateSystemCredentialsNotFound() {
	systemID := strconv.FormatUint(uint64(9999), 10)
	req := httptest.NewRequest("DELETE", "/system/"+systemID+"/credentials", nil)
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	handler := http.HandlerFunc(deactivateSystemCredentials)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	_ = Server()
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestDeactivateSystemCredentials() {
	logger := ssas.GetLogger(ssas.Logger)
	logHook := test.NewLocal(logger)
	group := ssas.Group{GroupID: "test-deactivate-creds-group", XData: string(`{"cms_ids":["A9999"]}`)}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-deactivate-creds-client"}
	s.db.Create(&system)
	secret := ssas.Secret{Hash: "test-deactivate-creds-hash", SystemID: system.ID}
	s.db.Create(&secret)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("DELETE", "/system/"+systemID+"/credentials", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.Handler(service.NewCtxLogger(http.HandlerFunc(deactivateSystemCredentials)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)

	logs := logHook.AllEntries()
	alertLog := false
	for _, v := range logs {
		if strings.Contains(v.Message, "A9999") {
			alertLog = true
		}
	}

	// verify the logging used for aco alerts
	assert.True(s.T(), alertLog)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestJSONError() {
	rr := httptest.NewRecorder()
	service.JSONError(rr, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "unauthorized")

	b, _ := io.ReadAll(rr.Body)
	var error ssas.ErrorResponse
	_ = json.Unmarshal(b, &error)

	assert.Equal(s.T(), "Unauthorized", error.Error)
	assert.Equal(s.T(), "unauthorized", error.ErrorDescription)
}

func (s *APITestSuite) TestGetSystemIPs() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("GET", "/system/"+systemID+"/ip", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getSystemIPs)

	//No ips
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var ips []ssas.IP
	_ = json.Unmarshal(rr.Body.Bytes(), &ips)
	assert.Empty(s.T(), ips)

	//Single IP
	ip1 := ssas.IP{Address: "2.5.1.1", SystemID: system.ID}
	s.db.Create(&ip1)

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	_ = json.Unmarshal(rr.Body.Bytes(), &ips)
	assert.NotEmpty(s.T(), ips)

	//Multiple IPs (should include ip1 created previously)
	ip2 := ssas.IP{Address: "2.5.1.2", SystemID: system.ID}
	s.db.Create(&ip2)
	ip3 := ssas.IP{Address: "2.5.1.3", SystemID: system.ID}
	s.db.Create(&ip3)

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	_ = json.Unmarshal(rr.Body.Bytes(), &ips)
	assert.NotEmpty(s.T(), ips)
	assert.Len(s.T(), ips, 3)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestGetSystemIPsBadSystem() {
	//Should not exist
	badSysId := 42

	systemID := strconv.FormatUint(uint64(badSysId), 10) // #nosec G115
	req := httptest.NewRequest("GET", "/system/"+systemID+"/ip", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getSystemIPs)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestRegisterSystemIP() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	body := `{"address":"2.5.22.81"}`
	req := httptest.NewRequest("POST", "/system/"+systemID+"/ip", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(registerIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))

	//Retrieve to confirm
	req = httptest.NewRequest("GET", "/system/"+systemID+"/ip", nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = getSystemIPs

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var ips []ssas.IP
	_ = json.Unmarshal(rr.Body.Bytes(), &ips)
	assert.Len(s.T(), ips, 1)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestRegisterInvalidIP() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	body := `{"address":"600.1"}`
	req := httptest.NewRequest("POST", "/system/"+systemID+"/ip", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(registerIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestRegisterMaxSystemIP() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)

	ip1 := ssas.IP{Address: "2.5.22.81", SystemID: system.ID}
	s.db.Create(&ip1)
	ip2 := ssas.IP{Address: "2.5.22.82", SystemID: system.ID}
	s.db.Create(&ip2)
	ip3 := ssas.IP{Address: "2.5.22.83", SystemID: system.ID}
	s.db.Create(&ip3)

	//Max is 3 (for test), 4th should produce error
	systemID := strconv.FormatUint(uint64(system.ID), 10)
	body := `{"address":"2.5.22.84"}`
	req := httptest.NewRequest("POST", "/system/"+systemID+"/ip", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(registerIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
	assert.Contains(s.T(), rr.Body.String(), "max ip addresses reached")
	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestRegisterDuplicateSystemIP() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)

	ip1 := ssas.IP{Address: "2.5.22.81", SystemID: system.ID}
	s.db.Create(&ip1)
	ip2 := ssas.IP{Address: "2.5.22.82", SystemID: system.ID}
	s.db.Create(&ip2)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	body := `{"address":"2.5.22.81"}`
	req := httptest.NewRequest("POST", "/system/"+systemID+"/ip", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(registerIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusConflict, rr.Result().StatusCode)
	assert.Contains(s.T(), rr.Body.String(), "duplicate ip address")
	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestRegisterSystemIPInvalidBody() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	body := `{"addr":"2.5.22.81"}`
	req := httptest.NewRequest("POST", "/system/"+systemID+"/ip", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(registerIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestRegisterSystemIPSystemNotFound() {
	body := `{"address":"2.5.22.81"}`
	req := httptest.NewRequest("POST", "/system/123/ip", strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", "123")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(registerIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestDeleteIP() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-reset-creds-client"}
	s.db.Create(&system)

	ip1 := ssas.IP{Address: "2.5.22.81", SystemID: system.ID}
	s.db.Create(&ip1)
	ip2 := ssas.IP{Address: "2.5.22.82", SystemID: system.ID}
	s.db.Create(&ip2)

	// Fetch IPs associated with system
	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("GET", "/system/"+systemID+"/ip", nil)
	rctx := chi.NewRouteContext()

	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getSystemIPs)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var ips []ssas.IP
	_ = json.Unmarshal(rr.Body.Bytes(), &ips)
	assert.Len(s.T(), ips, 2)

	// Get ID of first IP associated with system
	ipID := strconv.FormatUint(uint64(ips[0].ID), 10)

	// Delete IP
	req = httptest.NewRequest("DELETE", "/system/"+systemID+"/ip/"+ipID, nil)
	rctx.URLParams.Add("id", ipID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = deleteSystemIP

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Test that the IP was deleted
	assert.Equal(s.T(), http.StatusNoContent, rr.Result().StatusCode)
	assert.Equal(s.T(), strconv.FormatUint(uint64(ips[0].ID), 10), ipID)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestDeleteIPSystemNotFound() {
	req := httptest.NewRequest("DELETE", "/system/123/ip/123", nil)
	rctx := chi.NewRouteContext()

	rctx.URLParams.Add("id", "123")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(deleteSystemIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestDeleteIPIPNotFound() {
	group := ssas.Group{GroupID: "test-delete-ip-ip-not-found-group"}
	s.db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "test-delete-ip-ip-not-found-client"}
	s.db.Create(&system)

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("DELETE", "/system/"+systemID+"/ip/123", nil)
	rctx := chi.NewRouteContext()

	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(deleteSystemIP)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestUpdateSystem() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	//Create system
	req := httptest.NewRequest("POST", "/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhxobShmNifzW3xznB+L\nI8+hgaePpSGIFCtFz2IXGU6EMLdeufhADaGPLft9xjwdN1ts276iXQiaChKPA2CK\n/CBpuKcnU3LhU8JEi7u/db7J4lJlh6evjdKVKlMuhPcljnIKAiGcWln3zwYrFCeL\ncN0aTOt4xnQpm8OqHawJ18y0WhsWT+hf1DeBDWvdfRuAPlfuVtl3KkrNYn1yqCgQ\nlT6v/WyzptJhSR1jxdR7XLOhDGTZUzlHXh2bM7sav2n1+sLsuCkzTJqWZ8K7k7cI\nXK354CNpCdyRYUAUvr4rORIAUmcIFjaR3J4y/Dh2JIyDToOHg7vjpCtNnNoS+ON2\nHwIDAQAB\n-----END PUBLIC KEY-----", "tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.Equal(s.T(), "Test Client", result["client_name"])
	sysId := result["system_id"].(string)

	//Update Client name
	req = httptest.NewRequest("Patch", V2_SYSTEM_ROUTE+sysId, strings.NewReader(`{"client_name": "Updated Client Name"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(sysId))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = http.HandlerFunc(updateSystem)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNoContent, rr.Result().StatusCode)

	//Verify patch
	sys, err := ssas.GetSystemByID(context.Background(), sysId)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "Updated Client Name", sys.ClientName)

	//Update API Scope
	req = httptest.NewRequest("Patch", V2_SYSTEM_ROUTE+sysId, strings.NewReader(`{"api_scope": "updated_scope"}`))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = http.HandlerFunc(updateSystem)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNoContent, rr.Result().StatusCode)

	//Verify API Scope patch
	sys, err = ssas.GetSystemByID(context.Background(), sysId)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "updated_scope", sys.APIScope)

	//Update Software Id
	req = httptest.NewRequest("Patch", V2_SYSTEM_ROUTE+sysId, strings.NewReader(`{"software_id": "42"}`))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = http.HandlerFunc(updateSystem)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNoContent, rr.Result().StatusCode)

	//Verify Software Id patch
	sys, err = ssas.GetSystemByID(context.Background(), sysId)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "42", sys.SoftwareID)

	//Update prohibited attributes
	req = httptest.NewRequest("Patch", V2_SYSTEM_ROUTE+sysId, strings.NewReader(`{"client_id": "42"}`))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = http.HandlerFunc(updateSystem)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	result = make(map[string]interface{})
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
	assert.Equal(s.T(), "attribute: client_id is not valid", result["error_description"])

	//Update attributes with empty string
	req = httptest.NewRequest("Patch", V2_SYSTEM_ROUTE+sysId, strings.NewReader(`{"api_scope": ""}`))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = http.HandlerFunc(updateSystem)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	result = make(map[string]interface{})
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
	assert.Equal(s.T(), "attribute: api_scope may not be empty", result["error_description"])

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}
func (s *APITestSuite) TestUpdateSystemWithInvalidBody() {
	req := httptest.NewRequest("Patch", V2_SYSTEM_ROUTE+"0", strings.NewReader(`{"client_name": invalid json`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "0")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(updateSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
	assert.Contains(s.T(), rr.Body.String(), "invalid request body")
}

func (s *APITestSuite) TestUpdateNonExistingSystem() {
	req := httptest.NewRequest("Patch", V2_SYSTEM_ROUTE+"-1", strings.NewReader(`{"client_name":"updated_client"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "-1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(updateSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
	assert.Contains(s.T(), rr.Body.String(), "failed to update system")
}

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

// V2 Tests Below
func (s *APITestSuite) TestCreateV2System() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/v2/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id","xdata":"{\"org\":\"testOrgID\"}", "scope": "bcda-api", "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhxobShmNifzW3xznB+L\nI8+hgaePpSGIFCtFz2IXGU6EMLdeufhADaGPLft9xjwdN1ts276iXQiaChKPA2CK\n/CBpuKcnU3LhU8JEi7u/db7J4lJlh6evjdKVKlMuhPcljnIKAiGcWln3zwYrFCeL\ncN0aTOt4xnQpm8OqHawJ18y0WhsWT+hf1DeBDWvdfRuAPlfuVtl3KkrNYn1yqCgQ\nlT6v/WyzptJhSR1jxdR7XLOhDGTZUzlHXh2bM7sav2n1+sLsuCkzTJqWZ8K7k7cI\nXK354CNpCdyRYUAUvr4rORIAUmcIFjaR3J4y/Dh2JIyDToOHg7vjpCtNnNoS+ON2\nHwIDAQAB\n-----END PUBLIC KEY-----", "tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createV2System)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.NotEmpty(s.T(), result["client_id"])
	assert.Equal(s.T(), result["xdata"], "{\"org\":\"testOrgID\"}")
	assert.NotEmpty(s.T(), result["client_token"])
	assert.Empty(s.T(), result["client_secret"])
	assert.Equal(s.T(), "Test Client", result["client_name"])

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateV2SystemWithMissingPublicKey() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/v2/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createV2System)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)

	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	assert.Empty(s.T(), result["client_token"])
	assert.Equal(s.T(), "could not create system", result["error_description"])

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateV2SystemMultipleIps() {
	randomIPv4 := ssas.RandomIPv4()
	randomIPv6 := ssas.RandomIPv6()
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	reqBody := fmt.Sprintf(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "ips": ["%s", "%s"],"public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhxobShmNifzW3xznB+L\nI8+hgaePpSGIFCtFz2IXGU6EMLdeufhADaGPLft9xjwdN1ts276iXQiaChKPA2CK\n/CBpuKcnU3LhU8JEi7u/db7J4lJlh6evjdKVKlMuhPcljnIKAiGcWln3zwYrFCeL\ncN0aTOt4xnQpm8OqHawJ18y0WhsWT+hf1DeBDWvdfRuAPlfuVtl3KkrNYn1yqCgQ\nlT6v/WyzptJhSR1jxdR7XLOhDGTZUzlHXh2bM7sav2n1+sLsuCkzTJqWZ8K7k7cI\nXK354CNpCdyRYUAUvr4rORIAUmcIFjaR3J4y/Dh2JIyDToOHg7vjpCtNnNoS+ON2\nHwIDAQAB\n-----END PUBLIC KEY-----","tracking_id": "T00000"}`, randomIPv4, randomIPv6)
	req := httptest.NewRequest("POST", "/v2/system", strings.NewReader(reqBody))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createV2System)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))

	creds := ssas.Credentials{}
	err = json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&creds)
	assert.Nil(s.T(), err)
	assert.NotEmpty(s.T(), creds)
	assert.NotEqual(s.T(), "", creds.ClientID)
	assert.Equal(s.T(), "Test Client", creds.ClientName)

	system, err := ssas.GetSystemByClientID(req.Context(), creds.ClientID)
	assert.Nil(s.T(), err)
	ips, err := system.GetIPs()
	assert.Nil(s.T(), err)
	assert.True(s.T(), contains(ips, randomIPv4))
	assert.True(s.T(), contains(ips, randomIPv6))

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateV2SystemBadIp() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/v2/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", ips: ["304.0.2.1/32"],"tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createV2System)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateV2SystemEmptyKey() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/v2/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "public_key": "", "tracking_id": "T00000"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createV2System)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)

	var result map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)

	assert.Empty(s.T(), result["client_token"])
	assert.Equal(s.T(), "could not create system", result["error_description"])

	err = ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateV2SystemInvalidRequest() {
	req := httptest.NewRequest("POST", "/v2/system", strings.NewReader("{ badJSON }"))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createV2System)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreateV2SystemMissingRequiredParam() {
	req := httptest.NewRequest("POST", "/v2/system", strings.NewReader(`{"group_id": "T00001", "client_name": "Test Client 1", "scope": "bcda-api"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createV2System)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestGetV2System() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)
	req := httptest.NewRequest("GET", fmt.Sprintf("/v2/system/%s", creds.SystemID), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	b, _ := io.ReadAll(rr.Body)
	var system ssas.SystemOutput
	_ = json.Unmarshal(b, &system)

	assert.NotNil(s.T(), system.GID)
	assert.NotNil(s.T(), system.GroupID)
	assert.Equal(s.T(), creds.ClientID, system.ClientID)
	assert.NotNil(s.T(), system.SoftwareID)
	assert.Equal(s.T(), creds.ClientName, system.ClientName)
	assert.NotNil(s.T(), system.APIScope)
	assert.Equal(s.T(), system.XData, creds.XData)
	assert.NotNil(s.T(), system.LastTokenAt)
	assert.Len(s.T(), system.PublicKeys, 1)
	assert.Len(s.T(), system.IPs, len(creds.IPs))
	assert.Len(s.T(), system.ClientTokens, 1)
	assert.Equal(s.T(), system.IPs[0].IP, creds.IPs[0])
}

func (s *APITestSuite) TestGetV2SystemInactive() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)
	s.db.Delete(&ssas.System{}, creds.SystemID)

	req := httptest.NewRequest("GET", fmt.Sprintf("/v2/system/%s", creds.SystemID), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(getSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	b, _ := io.ReadAll(rr.Body)
	var error ssas.ErrorResponse
	_ = json.Unmarshal(b, &error)

	assert.Equal(s.T(), fmt.Sprintf("could not find system %s", creds.SystemID), error.ErrorDescription)
}

func (s *APITestSuite) TestCreateAndDeleteAdditionalV2SystemToken() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)

	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/token", creds.SystemID), strings.NewReader(`{"label":"hello"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	//verify it created a new client token
	b, _ := io.ReadAll(rr.Body)
	var clr ssas.ClientTokenResponse
	_ = json.Unmarshal(b, &clr)
	assert.NotNil(s.T(), clr.Token)
	assert.Equal(s.T(), "hello", clr.Label)

	req = httptest.NewRequest("GET", fmt.Sprintf("/v2/system/%s", creds.SystemID), nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = getSystem
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	b, _ = io.ReadAll(rr.Body)
	var system ssas.SystemOutput
	_ = json.Unmarshal(b, &system)

	assert.Len(s.T(), system.ClientTokens, 2)
	assert.Equal(s.T(), "hello", system.ClientTokens[1].Label)

	//delete the token
	req = httptest.NewRequest("DELETE", fmt.Sprintf("/v2/system/%s/token/%s", creds.SystemID, system.ClientTokens[1].UUID), strings.NewReader(`{"label":"hello"}`))
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	rctx.URLParams.Add("id", system.ClientTokens[1].UUID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = deleteToken
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	//verify the token is deleted
	req = httptest.NewRequest("GET", fmt.Sprintf("/v2/system/%s", creds.SystemID), nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = getSystem
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	b, _ = io.ReadAll(rr.Body)
	_ = json.Unmarshal(b, &system)

	assert.Len(s.T(), system.ClientTokens, 1)
}

func (s *APITestSuite) TestCreateV2SystemTokenSystemNotFound() {
	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/token", "fake-token"), strings.NewReader(`{"label":"hello"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", "fake-token")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreateV2SystemTokenNonJson() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)

	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/token", creds.SystemID), strings.NewReader(`"notalabel":"hello"}`))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	handler := http.HandlerFunc(createToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// TODO(BCDA-7212): Handle gracefully
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreateV2SystemTokenMissingLabel() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)

	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/token", creds.SystemID), strings.NewReader(`{"notalabel":"hello"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestDeleteV2SystemTokenSystemNotFound() {
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/v2/system/%s/token/%s", "fake-token", "fake-uuid"), strings.NewReader(`{"label":"hello"}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", "fake-token")
	rctx.URLParams.Add("id", "fake-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(deleteToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreateAndDeletePublicKey() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)

	key, sig, _, _ := ssas.GeneratePublicKey(2048)
	keyStr := strings.ReplaceAll(key, "\n", "\\n")
	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/key", creds.SystemID), strings.NewReader(fmt.Sprintf(`{"public_key":"%s", "signature":"%s"}`, keyStr, sig)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	//verify it created the new key
	b, _ := io.ReadAll(rr.Body)
	var responseMap map[string]string
	_ = json.Unmarshal(b, &responseMap)
	assert.NotNil(s.T(), string(b))
	assert.NotNil(s.T(), responseMap["id"])
	assert.NotNil(s.T(), responseMap["client_id"])
	assert.NotNil(s.T(), responseMap["public_key"])

	req = httptest.NewRequest("GET", fmt.Sprintf("/v2/system/%s", creds.SystemID), nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = getSystem
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	b, _ = io.ReadAll(rr.Body)
	var system ssas.SystemOutput
	_ = json.Unmarshal(b, &system)

	assert.Len(s.T(), system.PublicKeys, 2)
	assert.Equal(s.T(), key, system.PublicKeys[1].Key)

	//delete the key
	req = httptest.NewRequest("DELETE", fmt.Sprintf("/v2/system/%s/key/%s", creds.SystemID, system.PublicKeys[1].ID), nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	rctx.URLParams.Add("id", system.PublicKeys[1].ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = deleteKey
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	//verify the key is deleted
	req = httptest.NewRequest("GET", fmt.Sprintf("/v2/system/%s", creds.SystemID), nil)
	rctx = chi.NewRouteContext()
	rctx.URLParams.Add("id", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler = getSystem
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	b, _ = io.ReadAll(rr.Body)
	_ = json.Unmarshal(b, &system)

	assert.Len(s.T(), system.PublicKeys, 1)
}

func (s *APITestSuite) TestCreatePublicKeySystemNotFound() {
	key, sig, _, _ := ssas.GeneratePublicKey(2048)
	keyStr := strings.ReplaceAll(key, "\n", "\\n")
	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/key", "fake-token"), strings.NewReader(fmt.Sprintf(`{"public_key":"%s", "signature":"%s"}`, keyStr, sig)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", "fake-token")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreatePublicKeyNonJson() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)

	key, sig, _, _ := ssas.GeneratePublicKey(2048)
	keyStr := strings.ReplaceAll(key, "\n", "\\n")
	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/key", creds.SystemID), strings.NewReader(fmt.Sprintf(`"public_abcd":"%s", "signature":"%s"}`, keyStr, sig)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreatePublicKeyMissingFields() {
	creds, _ := ssas.CreateTestXDataV2(s.T(), s.db)

	key, sig, _, _ := ssas.GeneratePublicKey(2048)
	keyStr := strings.ReplaceAll(key, "\n", "\\n")
	req := httptest.NewRequest("POST", fmt.Sprintf("/v2/system/%s/key", creds.SystemID), strings.NewReader(fmt.Sprintf(`{"public_abcd":"%s", "signature":"%s"}`, keyStr, sig)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", creds.SystemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// TODO(BCDA-7212): Handle gracefully
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestDeletePublicKeySystemNotFound() {
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/v2/system/%s/key/%s", "fake-token", "fake-key"), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", "fake-token")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(context.WithValue(req.Context(), ssas.CtxLoggerKey, s.logEntry))
	handler := http.HandlerFunc(createKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusNotFound, rr.Result().StatusCode)
}

func MakeTestStructuredLoggerEntry(logFields logrus.Fields) *ssas.APILoggerEntry {
	var lggr logrus.Logger
	newLogEntry := &ssas.APILoggerEntry{Logger: lggr.WithFields(logFields)}
	return newLogEntry
}

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/go-chi/chi"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
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

const SampleXdata string = `"{\"cms_ids\":[\"T67890\",\"T54321\"]}"`

type APITestSuite struct {
	suite.Suite
	db *gorm.DB
}

func (s *APITestSuite) SetupSuite() {
	ssas.InitializeSystemModels()
	s.db = ssas.GetGORMDbConnection()
	service.StartBlacklist()
}

func (s *APITestSuite) TearDownSuite() {
	ssas.Close(s.db)
}

func (s *APITestSuite) TestCreateGroup() {
	gid := ssas.RandomBase64(16)
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)
	req := httptest.NewRequest("POST", "/group", strings.NewReader(testInput))
	handler := http.HandlerFunc(createGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	g := ssas.Group{}
	if s.db.Where("group_id = ?", gid).Find(&g).RecordNotFound() {
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
	handler := http.HandlerFunc(createGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	g := ssas.Group{}
	if s.db.Where("group_id = ?", gid).Find(&g).RecordNotFound() {
		assert.FailNow(s.T(), fmt.Sprintf("record not found for group_id=%s", gid))
	}
	err := ssas.CleanDatabase(g)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestListGroups() {
	g1ID := ssas.RandomBase64(16)
	g2ID := ssas.RandomHexID()

	testInput1 := fmt.Sprintf(SampleGroup, g1ID, SampleXdata)
	gd := ssas.GroupData{}
	err := json.Unmarshal([]byte(testInput1), &gd)
	assert.Nil(s.T(), err)
	g1, err := ssas.CreateGroup(gd, ssas.RandomHexID())
	assert.Nil(s.T(), err)

	gd.GroupID = g2ID
	gd.Name = "another-fake-name"
	g2, err := ssas.CreateGroup(gd, ssas.RandomHexID())
	assert.Nil(s.T(), err)

	req := httptest.NewRequest("GET", "/group", nil)
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
		case g1ID: found1 = true
		case g2ID: found2 = true
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
	g, err := ssas.CreateGroup(gd, ssas.RandomHexID())
	assert.Nil(s.T(), err)

	url := fmt.Sprintf("/group/%v", g.ID)
	req := httptest.NewRequest("PUT", url, strings.NewReader(testInput))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(g.ID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
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
	handler := http.HandlerFunc(revokeToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)

	assert.True(s.T(), service.TokenBlacklist.IsTokenBlacklisted(tokenID))
	assert.False(s.T(), service.TokenBlacklist.IsTokenBlacklisted("this_key_should_not_exist"))
}

func (s *APITestSuite) TestDeleteGroup() {
	gid := ssas.RandomHexID()
	testInput := fmt.Sprintf(SampleGroup, gid, SampleXdata)
	groupBytes := []byte(testInput)
	gd := ssas.GroupData{}
	err := json.Unmarshal(groupBytes, &gd)
	assert.Nil(s.T(), err)
	g, err := ssas.CreateGroup(gd, ssas.RandomHexID())
	assert.Nil(s.T(), err)

	url := fmt.Sprintf("/group/%v", g.ID)
	req := httptest.NewRequest("DELETE", url, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", fmt.Sprint(g.ID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	handler := http.HandlerFunc(deleteGroup)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	deleted := s.db.Find(&ssas.Group{}, g.ID).RecordNotFound()
	assert.True(s.T(), deleted)
	err = ssas.CleanDatabase(g)
	assert.Nil(s.T(), err)
}

func (s *APITestSuite) TestCreateSystem() {
	group := ssas.Group{GroupID: "test-group-id"}
	err := s.db.Save(&group).Error
	if err != nil {
		s.FailNow("Error creating test data", err.Error())
	}

	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader(`{"client_name": "Test Client", "group_id": "test-group-id", "scope": "bcda-api", "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhxobShmNifzW3xznB+L\nI8+hgaePpSGIFCtFz2IXGU6EMLdeufhADaGPLft9xjwdN1ts276iXQiaChKPA2CK\n/CBpuKcnU3LhU8JEi7u/db7J4lJlh6evjdKVKlMuhPcljnIKAiGcWln3zwYrFCeL\ncN0aTOt4xnQpm8OqHawJ18y0WhsWT+hf1DeBDWvdfRuAPlfuVtl3KkrNYn1yqCgQ\nlT6v/WyzptJhSR1jxdR7XLOhDGTZUzlHXh2bM7sav2n1+sLsuCkzTJqWZ8K7k7cI\nXK354CNpCdyRYUAUvr4rORIAUmcIFjaR3J4y/Dh2JIyDToOHg7vjpCtNnNoS+ON2\nHwIDAQAB\n-----END PUBLIC KEY-----", "tracking_id": "T00000"}`))
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

	system, err := ssas.GetSystemByClientID(creds.ClientID)
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

func (s *APITestSuite) TestCreateSystem_InvalidRequest() {
	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader("{ badJSON }"))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestCreateSystem_MissingRequiredParam() {
	req := httptest.NewRequest("POST", "/auth/system", strings.NewReader(`{"group_id": "T00001", "client_name": "Test Client 1", "scope": "bcda-api"}`))
	handler := http.HandlerFunc(createSystem)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusBadRequest, rr.Result().StatusCode)
}

func (s *APITestSuite) TestResetCredentials() {
	group := ssas.Group{GroupID: "test-reset-creds-group"}
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
	handler := http.HandlerFunc(resetCredentials)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusCreated, rr.Result().StatusCode)
	assert.Equal(s.T(), "application/json", rr.Result().Header.Get("Content-Type"))
	var result map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	newSecret := result["client_secret"]
	assert.NotEmpty(s.T(), newSecret)
	assert.NotEqual(s.T(), secret.Hash, newSecret)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestResetCredentials_InvalidSystemID() {
	systemID := "999"
	req := httptest.NewRequest("PUT", "/system/"+systemID+"/credentials", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
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

func (s *APITestSuite) TestGetPublicKey_Rotation() {
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

	key1, _ := ssas.GeneratePublicKey(2048)
	err = system.SavePublicKey(strings.NewReader(key1))
	if err != nil {
		s.FailNow(err.Error())
	}

	key2, _ := ssas.GeneratePublicKey(2048)
	err = system.SavePublicKey(strings.NewReader(key2))
	if err != nil {
		s.FailNow(err.Error())
	}

	systemID := strconv.FormatUint(uint64(system.ID), 10)
	req := httptest.NewRequest("GET", "/system/"+systemID+"/key", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("systemID", systemID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
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
	group := ssas.Group{GroupID: "test-deactivate-creds-group"}
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
	handler := http.HandlerFunc(deactivateSystemCredentials)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)

	_ = ssas.CleanDatabase(group)
}

func (s *APITestSuite) TestJsonError() {
	w := httptest.NewRecorder()
	jsonError(w, http.StatusUnauthorized, "unauthorized")
	resp := w.Result()
	body, err := ioutil.ReadAll(resp.Body)
	assert.NoError(s.T(), err)
	assert.True(s.T(), json.Valid(body))
	assert.Equal(s.T(), `{"error":"Unauthorized","error_description":"unauthorized"}`, string(body))
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

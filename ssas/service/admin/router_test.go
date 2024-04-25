package admin

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RouterTestSuite struct {
	suite.Suite
	router    http.Handler
	basicAuth string
	badAuth   string
	group     ssas.Group
}

func (s *RouterTestSuite) SetupSuite() {
	encSecret, err := ssas.ResetAdminCreds()
	assert.NoError(s.T(), err)

	s.basicAuth = encSecret

	badAuth := "31e029ef-0e97-47f8-873c-0e8b7e7f99bf:This_is_not_the_secret"
	s.badAuth = base64.StdEncoding.EncodeToString([]byte(badAuth))
}

func (s *RouterTestSuite) SetupTest() {
	s.router = routes()
}

func (s *RouterTestSuite) TearDownSuite() {
	_ = ssas.CleanDatabase(s.group)
}

func (s *RouterTestSuite) TestUnauthorized() {
	req := httptest.NewRequest("GET", "/group", nil)
	basicAuth := base64.StdEncoding.EncodeToString([]byte("bad:creds"))
	req.Header.Add("Authorization", "Basic "+basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusUnauthorized, res.StatusCode)
}

func (s *RouterTestSuite) TestNonBasicAuth() {
	req := httptest.NewRequest("GET", "/group", nil)
	req.Header.Add("Authorization", "This is not a base64-encoded username/password pair!")
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusBadRequest, res.StatusCode)
}

func (s *RouterTestSuite) TestBadSecret() {
	req := httptest.NewRequest("GET", "/group", nil)
	req.Header.Add("Authorization", "Basic "+s.badAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusUnauthorized, res.StatusCode)
}

func (s *RouterTestSuite) TestRevokeToken() {
	req := httptest.NewRequest("DELETE", "/token/abc-123", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)
}

func (s *RouterTestSuite) TestPostGroup() {
	req := httptest.NewRequest("POST", "/group", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusBadRequest, res.StatusCode)
}

func (s *RouterTestSuite) TestGetGroup() {
	req := httptest.NewRequest("GET", "/group", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)
}

func (s *RouterTestSuite) TestPutGroup() {
	req := httptest.NewRequest("PUT", "/group/1", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusBadRequest, res.StatusCode)
}

func (s *RouterTestSuite) TestDeleteGroup() {
	req := httptest.NewRequest("DELETE", "/group/101", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusNotFound, res.StatusCode)
}

func (s *RouterTestSuite) TestPostSystem() {
	req := httptest.NewRequest("POST", "/system", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusBadRequest, res.StatusCode)
}

func (s *RouterTestSuite) TestDeactivateSystemCredentials() {
	db := ssas.Connection
	group := ssas.Group{GroupID: "delete-system-credentials-test-group"}
	db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "delete-system-credentials-test-system"}
	db.Create(&system)
	systemID := strconv.FormatUint(uint64(system.ID), 10)

	req := httptest.NewRequest("DELETE", "/system/"+systemID+"/credentials", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)

	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *RouterTestSuite) TestPutSystemCredentials() {
	db := ssas.Connection
	group := ssas.Group{GroupID: "put-system-credentials-test-group"}
	db.Create(&group)
	system := ssas.System{GID: group.ID, ClientID: "put-system-credentials-test-system"}
	db.Create(&system)
	systemID := strconv.FormatUint(uint64(system.ID), 10)

	req := httptest.NewRequest("PUT", "/system/"+systemID+"/credentials", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusCreated, res.StatusCode)

	err := ssas.CleanDatabase(group)
	assert.Nil(s.T(), err)
}

func (s *RouterTestSuite) TestPostV2Group() {
	req := httptest.NewRequest("POST", "/v2/group", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusBadRequest, res.StatusCode)
}

func (s *RouterTestSuite) TestGetV2Group() {
	req := httptest.NewRequest("GET", "/v2/group", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)
}

func (s *RouterTestSuite) TestPatchV2Group() {
	req := httptest.NewRequest(http.MethodPatch, "/v2/group/1", nil)
	req.Header.Add("Authorization", "Basic "+s.basicAuth)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	res := rr.Result()
	assert.Equal(s.T(), http.StatusBadRequest, res.StatusCode)
}

func TestRouterTestSuite(t *testing.T) {
	suite.Run(t, new(RouterTestSuite))
}

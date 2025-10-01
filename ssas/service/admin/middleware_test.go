package admin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type AdminMiddlewareTestSuite struct {
	suite.Suite
	server    *httptest.Server
	rr        *httptest.ResponseRecorder
	basicAuth string
	badAuth   string
	h         *adminMiddlewareHandler
	db        *gorm.DB
}

func (s *AdminMiddlewareTestSuite) CreateRouter(handlers ...func(http.Handler) http.Handler) http.Handler {
	router := chi.NewRouter()
	router.With(handlers...).Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Test router"))
		if err != nil {
			log.Fatal(err)
		}
	})

	return router
}
func (s *AdminMiddlewareTestSuite) SetupSuite() {
	cfg.LoadEnvConfigs()

}
func (s *AdminMiddlewareTestSuite) TearDownTest() {
	db, err := s.db.DB()
	require.NoError(s.T(), err)
	db.Close()
}

func (s *AdminMiddlewareTestSuite) SetupTest() {
	var err error
	s.db, err = ssas.CreateDB()
	require.NoError(s.T(), err)
	s.rr = httptest.NewRecorder()
	encCreds, err := ssas.ResetCreds(s.db, service.TestAdminClientID, "admin")
	assert.NoError(s.T(), err)
	s.basicAuth = encCreds

	badAuth := fmt.Sprintf("%s:This_is_not_the_secret", service.TestAdminClientID)
	s.badAuth = base64.StdEncoding.EncodeToString([]byte(badAuth))
	s.h = NewAdminMiddlewareHandler()
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthSuccess() {
	testAuth(s.basicAuth, http.StatusOK, s)
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthFailure() {
	r := testAuth(s.badAuth, http.StatusUnauthorized, s)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	var result map[string]interface{}
	_ = json.Unmarshal(b, &result)
	assert.Equal(s.T(), "invalid client secret", result["error_description"])
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthExpired() {
	ssas.ExpireAdminCreds(s.db)
	r := testAuth(s.basicAuth, http.StatusUnauthorized, s)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	var result map[string]interface{}
	_ = json.Unmarshal(b, &result)
	assert.Equal(s.T(), "credentials expired", result["error_description"])
}

func testAuth(base64Creds string, statusCode int, s *AdminMiddlewareTestSuite, customHandlers ...func(http.Handler) http.Handler) *http.Response {
	handlers := append([]func(http.Handler) http.Handler{s.h.requireBasicAuth}, customHandlers...)
	s.server = httptest.NewServer(s.CreateRouter(handlers...))
	client := s.server.Client()

	// Valid credentials should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Basic "+base64Creds)

	resp, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), statusCode, resp.StatusCode)

	return resp
}

func TestAdminMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(AdminMiddlewareTestSuite))
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthContext() {
	oldFFVal := os.Getenv("SGA_ADMIN_FEATURE")
	os.Setenv("SGA_ADMIN_FEATURE", "true")

	testAuth(s.basicAuth, http.StatusOK, s, verifyContext)

	err := os.Setenv("SGA_ADMIN_FEATURE", oldFFVal)
	assert.Nil(s.T(), err)
}

func verifyContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sgaKey := r.Context().Value(constants.CtxSGAKey)
		skipAuth := r.Context().Value(constants.CtxSGASkipAuthKey)

		// set in service/main#addFixtureData()
		if sgaKey != "bcda" {
			w.WriteHeader(http.StatusNotFound)
		}
		if skipAuth != "true" {
			w.WriteHeader(http.StatusNotFound)
		}

		next.ServeHTTP(w, r)
	})
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthContext_NoSGA() {
	encCreds, err := ssas.ResetCreds(s.db, service.TestGroupID, service.TestGroupID)
	assert.NoError(s.T(), err)
	s.basicAuth = encCreds

	oldFFVal := os.Getenv("SGA_ADMIN_FEATURE")
	os.Setenv("SGA_ADMIN_FEATURE", "true")

	testAuth(s.basicAuth, http.StatusOK, s, verifyNoContext)

	err = os.Setenv("SGA_ADMIN_FEATURE", oldFFVal)
	assert.Nil(s.T(), err)
}

func verifyNoContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sgaKey := r.Context().Value(constants.CtxSGAKey)
		skipAuth := r.Context().Value(constants.CtxSGASkipAuthKey)
		fmt.Printf("\n--- vals found: %+v, %+v\n", sgaKey, skipAuth)
		if sgaKey != "test-sga" {
			w.WriteHeader(http.StatusNotFound)
		}
		if fmt.Sprintf("%v", skipAuth) != "<nil>" {
			w.WriteHeader(http.StatusNotFound)
		}

		next.ServeHTTP(w, r)
	})
}

package admin

import (
	"encoding/base64"
	"encoding/json"
	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

type AdminMiddlewareTestSuite struct {
	suite.Suite
	server    *httptest.Server
	rr        *httptest.ResponseRecorder
	basicAuth string
	badAuth   string
}

func (s *AdminMiddlewareTestSuite) CreateRouter(handler ...func(http.Handler) http.Handler) http.Handler {
	router := chi.NewRouter()
	router.With(handler...).Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Test router"))
		if err != nil {
			log.Fatal(err)
		}
	})

	return router
}

func (s *AdminMiddlewareTestSuite) SetupTest() {
	s.rr = httptest.NewRecorder()
	encCreds, err := ssas.ResetAdminCreds()
	assert.NoError(s.T(), err)
	s.basicAuth = encCreds

	badAuth := "31e029ef-0e97-47f8-873c-0e8b7e7f99bf:This_is_not_the_secret"
	s.badAuth = base64.StdEncoding.EncodeToString([]byte(badAuth))
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthSuccess() {
	s.server = httptest.NewServer(s.CreateRouter(requireBasicAuth))
	client := s.server.Client()

	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Basic "+s.basicAuth)

	resp, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthFailure() {
	s.server = httptest.NewServer(s.CreateRouter(requireBasicAuth))
	client := s.server.Client()

	// Valid credentials should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Basic "+s.badAuth)

	resp, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	var result map[string]interface{}
	_ = json.Unmarshal(b, &result)
	assert.Equal(s.T(), "invalid client secret", result["error_description"], string(b))
}

func (s *AdminMiddlewareTestSuite) TestRequireBasicAuthExpired() {
	ssas.ExpireAdminCreds()
	s.server = httptest.NewServer(s.CreateRouter(requireBasicAuth))
	client := s.server.Client()

	// Valid credentials should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Basic "+s.basicAuth)

	resp, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	var result map[string]interface{}
	_ = json.Unmarshal(b, &result)
	assert.Equal(s.T(), "credentials expired", result["error_description"], string(b))
}

func TestAdminMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(AdminMiddlewareTestSuite))
}
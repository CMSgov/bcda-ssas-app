package public

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var mockHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {}

type PublicMiddlewareTestSuite struct {
	suite.Suite
	server *httptest.Server
	rr     *httptest.ResponseRecorder
}

func (s *PublicMiddlewareTestSuite) CreateRouter(handler ...func(http.Handler) http.Handler) http.Handler {
	router := chi.NewRouter()
	router.With(handler...).Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Test router"))
		if err != nil {
			log.Fatal(err)
		}
	})

	return router
}

func (s *PublicMiddlewareTestSuite) SetupTest() {
	s.rr = httptest.NewRecorder()
}

func (s *PublicMiddlewareTestSuite) TestRequireTokenAuthWithInvalidSignature() {
	badToken := "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN" // #nosec G101 // gitleaks:allow

	testForToken :=
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value("token")
				assert.Nil(s.T(), token)
				_, err := readRegData(r)
				assert.NotNil(s.T(), err)
			})
		}
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, parseToken, testForToken))
	client := s.server.Client()

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Bearer "+badToken)

	resp, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *PublicMiddlewareTestSuite) TestParseTokenEmptyToken() {
	testForToken :=
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value("token")
				assert.Nil(s.T(), token)
				_, err := readRegData(r)
				assert.NotNil(s.T(), err)
			})
		}
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, parseToken, testForToken))
	client := s.server.Client()

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Authorization", "Bearer ")

	_, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *PublicMiddlewareTestSuite) TestParseTokenValidToken() {
	oktaID := "fake_okta_id"
	groupIDs := []string{"T0001", "T0002"}
	testForToken :=
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ts := r.Context().Value("ts")
				assert.NotNil(s.T(), ts)
				rd, err := readRegData(r)
				if err != nil {
					assert.FailNow(s.T(), err.Error())
				}
				assert.NotNil(s.T(), rd)
				assert.Equal(s.T(), oktaID, rd.OktaID)
				assert.Equal(s.T(), groupIDs, rd.AllowedGroupIDs)
			})
		}
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, parseToken, testForToken))
	client := s.server.Client()

	_, ts, _ := MintRegistrationToken(oktaID, groupIDs)

	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Bearer "+ts)

	res, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)
}

func (s *PublicMiddlewareTestSuite) TestRequireRegTokenAuthValidToken() {
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, requireRegTokenAuth))

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	handler := requireRegTokenAuth(mockHandler)

	groupIDs := []string{"A0001", "A0002"}
	token, ts, err := MintRegistrationToken("fake_okta_id", groupIDs)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), token)
	assert.NotNil(s.T(), ts)

	ctx := req.Context()
	ctx = context.WithValue(ctx, "ts", ts) //nolint:staticcheck
	req = req.WithContext(ctx)

	handler.ServeHTTP(s.rr, req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)
}

func (s *PublicMiddlewareTestSuite) TestRequireRegTokenAuthRevoked() {
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, requireMFATokenAuth))

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	handler := requireMFATokenAuth(mockHandler)

	groupIDs := []string{"A0001", "A0002"}
	token, ts, err := MintRegistrationToken("fake_okta_id", groupIDs)
	assert.Nil(s.T(), err)

	claims := token.Claims.(*service.CommonClaims)
	err = service.TokenDenylist.DenylistToken(req.Context(), claims.Id, service.TokenCacheLifetime)
	assert.Nil(s.T(), err)
	assert.True(s.T(), service.TokenDenylist.IsTokenDenylisted(claims.Id))

	assert.NotNil(s.T(), token)

	ctx := req.Context()
	ctx = context.WithValue(ctx, "ts", ts) //nolint:staticcheck
	req = req.WithContext(ctx)

	handler.ServeHTTP(s.rr, req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusUnauthorized, s.rr.Code)
}

func (s *PublicMiddlewareTestSuite) TestRequireRegTokenAuthEmptyToken() {
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, requireRegTokenAuth))
	client := s.server.Client()

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	ctx := context.WithValue(context.Background(), "ts", nil) //nolint:staticcheck

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (s *PublicMiddlewareTestSuite) TestGetTransactionID() {
	s.server = httptest.NewServer(s.CreateRouter(service.GetTransactionID, service.NewCtxLogger, requireRegTokenAuth))
	req, err := http.NewRequest("GET", s.server.URL, nil)
	req.Header.Add(service.TransactionIDHeader, "1234")

	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	handler := requireRegTokenAuth(mockHandler)

	groupIDs := []string{"A0001", "A0002"}
	token, ts, err := MintRegistrationToken("fake_okta_id", groupIDs)
	assert.NotNil(s.T(), token)

	ctx := req.Context()
	ctx = context.WithValue(ctx, "ts", ts) //nolint:staticcheck

	handler.ServeHTTP(s.rr, req.WithContext(ctx))
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, s.rr.Code)

	if tid, ok := req.Context().Value(service.CtxTransactionKey).(string); ok {
		assert.Equal(s.T(), tid, "1234")
	}
}

func (s *PublicMiddlewareTestSuite) TestVerifySGAAuthSkip_With_SGA_ADMIN_FEATURE() {
	oldFFVal := os.Getenv("SGA_ADMIN_FEATURE")
	os.Setenv("SGA_ADMIN_FEATURE", "true")

	testForSkip := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			skipCheck := r.Context().Value(constants.CtxSGASkipAuthKey).(string)
			assert.Equal(s.T(), "true", skipCheck)
		})
	}

	s.server = httptest.NewServer(s.CreateRouter(SkipSGAAuthCheck, testForSkip))
	client := s.server.Client()
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	resp, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	err = os.Setenv("SGA_ADMIN_FEATURE", oldFFVal)
	assert.Nil(s.T(), err)
}

func (s *PublicMiddlewareTestSuite) TestVerifySGAAuthSkip_Without_SGA_ADMIN_FEATURE() {
	oldFFVal := os.Getenv("SGA_ADMIN_FEATURE")
	os.Setenv("SGA_ADMIN_FEATURE", "false")

	testNoSkip := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			skipCheck := r.Context().Value(constants.CtxSGASkipAuthKey)
			assert.Equal(s.T(), "<nil>", fmt.Sprintf("%v", skipCheck))
		})
	}

	s.server = httptest.NewServer(s.CreateRouter(SkipSGAAuthCheck, testNoSkip))
	client := s.server.Client()
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	resp, err := client.Do(req)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)

	err = os.Setenv("SGA_ADMIN_FEATURE", oldFFVal)
	assert.Nil(s.T(), err)
}

func (s *PublicMiddlewareTestSuite) TestContains() {
	list := []string{"abc", "def", "hij", "hij"}
	assert.True(s.T(), contains(list, "abc"))
	assert.True(s.T(), contains(list, "def"))
	assert.True(s.T(), contains(list, "hij"))
	assert.False(s.T(), contains(list, "lmn"))
}

func TestPublicMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(PublicMiddlewareTestSuite))
}

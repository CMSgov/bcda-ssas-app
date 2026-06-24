package public

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var mockHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {}

type PublicMiddlewareTestSuite struct {
	suite.Suite
	server *httptest.Server
	rr     *httptest.ResponseRecorder
	h      *publicMiddlewareHandler
}

func (s *PublicMiddlewareTestSuite) SetupTest() {
	db, err := ssas.CreateDB()
	require.NoError(s.T(), err)
	s.h = NewPublicMiddlewareHandler(db)
	s.rr = httptest.NewRecorder()
}

func TestPublicMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(PublicMiddlewareTestSuite))
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
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, s.h.parseToken, testForToken))
	client := s.server.Client()

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Bearer "+badToken)

	resp, err := client.Do(req) // #nosec G704
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
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, s.h.parseToken, testForToken))
	client := s.server.Client()

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Authorization", "Bearer ")

	_, err = client.Do(req) // #nosec G704
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
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, s.h.parseToken, testForToken))
	client := s.server.Client()

	_, ts, _ := MintRegistrationToken(oktaID, groupIDs)

	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	req.Header.Add("Authorization", "Bearer "+ts)

	res, err := client.Do(req) // #nosec G704
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)
}

func (s *PublicMiddlewareTestSuite) TestRequireRegTokenAuthValidToken() {
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, s.h.requireRegTokenAuth))

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	handler := s.h.requireRegTokenAuth(mockHandler)

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
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, s.h.requireMFATokenAuth))

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	handler := s.h.requireMFATokenAuth(mockHandler)

	groupIDs := []string{"A0001", "A0002"}
	token, ts, err := MintRegistrationToken("fake_okta_id", groupIDs)
	assert.Nil(s.T(), err)

	claims := token.Claims.(*service.CommonClaims)
	err = service.TokenDenylist.DenylistToken(req.Context(), claims.ID, service.TokenCacheLifetime)
	assert.Nil(s.T(), err)
	assert.True(s.T(), service.TokenDenylist.IsTokenDenylisted(claims.ID))

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
	s.server = httptest.NewServer(s.CreateRouter(service.NewCtxLogger, s.h.requireRegTokenAuth))
	client := s.server.Client()

	// Valid token should return a 200 response
	req, err := http.NewRequest("GET", s.server.URL, nil)
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	ctx := context.WithValue(context.Background(), "ts", nil) //nolint:staticcheck

	resp, err := client.Do(req.WithContext(ctx)) // #nosec G704
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (s *PublicMiddlewareTestSuite) TestGetTransactionID() {
	s.server = httptest.NewServer(s.CreateRouter(service.GetTransactionID, service.NewCtxLogger, s.h.requireRegTokenAuth))
	req, err := http.NewRequest("GET", s.server.URL, nil)
	req.Header.Add(service.TransactionIDHeader, "1234")

	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}

	handler := s.h.requireRegTokenAuth(mockHandler)

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

func (s *PublicMiddlewareTestSuite) TestVerifySGAAuthSkip() {
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

	resp, err := client.Do(req) // #nosec G704
	if err != nil {
		assert.FailNow(s.T(), err.Error())
	}
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
}

func (s *PublicMiddlewareTestSuite) TestContains() {
	list := []string{"abc", "def", "hij", "hij"}
	assert.True(s.T(), contains(list, "abc"))
	assert.True(s.T(), contains(list, "def"))
	assert.True(s.T(), contains(list, "hij"))
	assert.False(s.T(), contains(list, "lmn"))
}

func (s *PublicMiddlewareTestSuite) TestTokenRateLimitMiddleware() {
	// Configure test limits
	cfg.RateLimitThreshold = 3
	cfg.RateLimitDurationMinutes = 1

	// Create a test group and system in DB
	groupID := ssas.RandomHexID()[0:4]
	// XData format: {"cms_ids": ["A9999"]}
	group := ssas.Group{GroupID: groupID, XData: `{"cms_ids":["A9999"]}`}
	err := s.h.db.Create(&group).Error
	require.Nil(s.T(), err)
	defer func() {
		assert.NoError(s.T(), ssas.CleanDatabase(group))
	}()

	creds, err := s.h.sr.RegisterSystem(context.Background(), "Limit Test", groupID, cfg.DefaultScope, "", []string{}, "tracking-limit-id")
	require.Nil(s.T(), err)

	// Create test handler and wrap it with middleware
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rateLimitedHandler := s.h.TokenRateLimitMiddleware(dummyHandler)

	// Make 3 requests (should all succeed as limit is 3)
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest("POST", "/token", nil)
		req.SetBasicAuth(creds.ClientID, creds.ClientSecret)
		rr := httptest.NewRecorder()

		rateLimitedHandler.ServeHTTP(rr, req)
		assert.Equal(s.T(), http.StatusOK, rr.Code, "Expected request %d to succeed", i)
	}

	// The 4th request should get a 429
	req4 := httptest.NewRequest("POST", "/token", nil)
	req4.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	rr4 := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(rr4, req4)
	assert.Equal(s.T(), http.StatusTooManyRequests, rr4.Code, "Expected request 4 to be rate limited (429)")

	// Request with a different Client ID (mapped to a different ACO) should NOT be rate limited
	groupID2 := ssas.RandomHexID()[0:4]
	group2 := ssas.Group{GroupID: groupID2, XData: `{"cms_ids":["A8888"]}`}
	err = s.h.db.Create(&group2).Error
	require.Nil(s.T(), err)
	defer func() {
		assert.NoError(s.T(), ssas.CleanDatabase(group2))
	}()

	creds2, err := s.h.sr.RegisterSystem(context.Background(), "Limit Test 2", groupID2, cfg.DefaultScope, "", []string{}, "tracking-limit-id-2")
	require.Nil(s.T(), err)

	reqDiff := httptest.NewRequest("POST", "/token", nil)
	reqDiff.SetBasicAuth(creds2.ClientID, creds2.ClientSecret)
	rrDiff := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(rrDiff, reqDiff)
	assert.Equal(s.T(), http.StatusOK, rrDiff.Code, "Request for a different ACO should succeed")
}

func (s *PublicMiddlewareTestSuite) TestTokenRateLimitMiddleware_NegativeCaching() {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rateLimitedHandler := s.h.TokenRateLimitMiddleware(dummyHandler)

	// Use a non-existent client ID
	invalidClientID := "non-existent-client-id"

	req := httptest.NewRequest("POST", "/token", nil)
	req.SetBasicAuth(invalidClientID, "secret")
	rr := httptest.NewRecorder()

	rateLimitedHandler.ServeHTTP(rr, req)

	// It should pass through because system doesn't exist (auth handler will reject it later)
	assert.Equal(s.T(), http.StatusOK, rr.Code)

	// The clientID should be negative cached
	val, found := s.h.clientIDToACOIDCache.Get(invalidClientID)
	assert.True(s.T(), found)
	assert.Equal(s.T(), invalidACOIDSentinel, val.(string))
}

func (s *PublicMiddlewareTestSuite) TestTokenRateLimitMiddleware_DynamicRetryAfter() {
	// Configure test limits
	cfg.RateLimitThreshold = 1
	cfg.RateLimitDurationMinutes = 3 // 3 minutes window

	// Create a test group and system in DB
	groupID := ssas.RandomHexID()[0:4]
	group := ssas.Group{GroupID: groupID, XData: `{"cms_ids":["A7777"]}`}
	err := s.h.db.Create(&group).Error
	require.Nil(s.T(), err)
	defer func() {
		assert.NoError(s.T(), ssas.CleanDatabase(group))
	}()

	creds, err := s.h.sr.RegisterSystem(context.Background(), "Retry Test", groupID, cfg.DefaultScope, "", []string{}, "tracking-retry-id")
	require.Nil(s.T(), err)

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rateLimitedHandler := s.h.TokenRateLimitMiddleware(dummyHandler)

	// 1st request -> success
	req1 := httptest.NewRequest("POST", "/token", nil)
	req1.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	rr1 := httptest.NewRecorder()
	rateLimitedHandler.ServeHTTP(rr1, req1)
	assert.Equal(s.T(), http.StatusOK, rr1.Code)

	// 2nd request -> 429 and Retry-After header
	req2 := httptest.NewRequest("POST", "/token", nil)
	req2.SetBasicAuth(creds.ClientID, creds.ClientSecret)
	rr2 := httptest.NewRecorder()
	rateLimitedHandler.ServeHTTP(rr2, req2)
	assert.Equal(s.T(), http.StatusTooManyRequests, rr2.Code)

	// Retry-After should be 3 minutes * 60 = 180 seconds
	assert.Equal(s.T(), "180", rr2.Header().Get("Retry-After"))
}

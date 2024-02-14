package service

import (
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/suite"
)

var mockHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {}

type LoggingTestSuite struct {
	suite.Suite
	server *httptest.Server
	rr     *httptest.ResponseRecorder
}

func (l *LoggingTestSuite) CreateRouter(handler ...func(http.Handler) http.Handler) http.Handler {
	router := chi.NewRouter()
	router.With(handler...).Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Test router"))
		if err != nil {
			log.Fatal(err)
		}
	})

	return router
}

// func (l *LoggingTestSuite) TestGetTransactionID() {
// 	l.server = httptest.NewServer(l.CreateRouter(NewCtxLogger, GetTransactionID))

// 	req, err := http.NewRequest("GET", l.server.URL, nil)
// 	if err != nil {
// 		assert.FailNow(l.T(), err.Error())
// 	}

// 	handler := requireRegTokenAuth(mockHandler)
// 	groupIDs := []string{"A0001", "A0002"}
// 	token, ts, err := public.MintRegistrationToken("fake_okta_id", groupIDs)
// 	assert.NotNil(l.T(), token)

// 	ctx := req.Context()
// 	ctx = context.WithValue(ctx, "ts", ts)

// 	handler.ServeHTTP(l.rr, req.WithContext(ctx))
// 	if err != nil {
// 		assert.FailNow(l.T(), err.Error())
// 	}
// 	assert.Equal(l.T(), http.StatusOK, l.rr.Code)
// }

func requireRegTokenAuth(next http.Handler) http.Handler {
	return tokenAuth(next, "RegistrationToken")
}

func tokenAuth(next http.Handler, tokenType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := ssas.Event{Op: "TokenAuth"}

		tsObj := r.Context().Value("ts")
		if tsObj == nil {
			event.Help = "no token string found"
			ssas.AuthorizationFailure(event)
			respond(w, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func respond(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

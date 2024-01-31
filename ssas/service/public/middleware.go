package public

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/CMSgov/bcda-ssas-app/log"
	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/sirupsen/logrus"
)

func readGroupID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			rd  ssas.AuthRegData
			err error
		)

		logger := log.GetCtxLogger(r.Context())

		if rd, err = readRegData(r); err != nil {
			logger.Println("no data from token about allowed groups")
			respond(w, http.StatusUnauthorized)
			return
		}

		if rd.GroupID = r.Header.Get("x-group-id"); rd.GroupID == "" {
			logger.Println("missing header x-group-id")
			respond(w, http.StatusUnauthorized)
			return
		}

		if !contains(rd.AllowedGroupIDs, rd.GroupID) {
			logger.Println("group specified in x-group-id not in token's allowed groups")
			respond(w, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "rd", rd)
		log.SetCtxEntry(r, "rd", rd)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Puts the decoded token, identity, and authorization values into the request context. Decoded values have been
// verified to be tokens signed by our server and to have not expired. Additional authorization
// occurs in requireRegTokenAuth() or requireMFATokenAuth().
func parseToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := logrus.Fields{"Op": "ParseToken"}
		logger := log.GetCtxLogger(r.Context()).WithFields(event)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			helpMsg := "no authorization header found"
			logger.Error(logrus.Fields{"Event": "AuthorizationFailure", "Help": helpMsg})
			next.ServeHTTP(w, r)
			return
		}

		authRegexp := regexp.MustCompile(`^Bearer (\S+)$`)
		authSubmatches := authRegexp.FindStringSubmatch(authHeader)
		if len(authSubmatches) < 2 {
			helpMsg := "invalid Authorization header value"
			logger.Error(logrus.Fields{"Event": "AuthorizationFailure", "Help": helpMsg})
			next.ServeHTTP(w, r)
			return
		}

		tokenString := authSubmatches[1]
		token, err := server.VerifyToken(tokenString)
		if err != nil {
			helpMsg := fmt.Sprintf("unable to decode authorization header value; %s", err)
			logger.Error(logrus.Fields{"Event": "AuthorizationFailure", "Help": helpMsg})
			next.ServeHTTP(w, r)
			return
		}

		var rd ssas.AuthRegData
		if rd, err = readRegData(r); err != nil {
			rd = ssas.AuthRegData{}
		}

		if claims, ok := token.Claims.(*service.CommonClaims); ok && token.Valid {
			rd.AllowedGroupIDs = claims.GroupIDs
			rd.OktaID = claims.OktaID
		}
		ctx := context.WithValue(r.Context(), "ts", tokenString)
		ctx = context.WithValue(ctx, "rd", rd)
		log.SetCtxEntry(r, "rd", rd)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireRegTokenAuth(next http.Handler) http.Handler {
	return tokenAuth(next, "RegistrationToken")
}

func requireMFATokenAuth(next http.Handler) http.Handler {
	return tokenAuth(next, "MFAToken")
}

func tokenAuth(next http.Handler, tokenType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ts string
			ok bool
		)
		event := ssas.Event{Op: "TokenAuth"}

		tsObj := r.Context().Value("ts")
		if tsObj == nil {
			event.Help = "no token string found"
			ssas.AuthorizationFailure(event)
			respond(w, http.StatusUnauthorized)
			return
		}
		ts, ok = tsObj.(string)
		if !ok {
			event.Help = "token string invalid"
			ssas.AuthorizationFailure(event)
			respond(w, http.StatusUnauthorized)
			return
		}

		err := tokenValidity(ts, tokenType)
		if err != nil {
			event.Help = "token invalid"
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

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

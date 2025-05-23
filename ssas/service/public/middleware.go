package public

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

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

		logger := ssas.GetCtxLogger(r.Context())

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

		ctx := context.WithValue(r.Context(), "rd", rd) //nolint:staticcheck
		ssas.SetCtxEntry(r, "rd", rd)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Puts the decoded token, identity, and authorization values into the request context. Decoded values have been
// verified to be tokens signed by our server and to have not expired. Additional authorization
// occurs in requireRegTokenAuth() or requireMFATokenAuth().
func parseToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := logrus.Fields{"Op": "ParseToken"}
		logger := ssas.GetCtxLogger(r.Context()).WithFields(event)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			helpMsg := "no authorization header found"
			ssas.SetCtxEntry(r, "Event", "AuthorizationFailure")
			logger.Error(helpMsg)
			next.ServeHTTP(w, r)
			return
		}

		authRegexp := regexp.MustCompile(`^Bearer (\S+)$`)
		authSubmatches := authRegexp.FindStringSubmatch(authHeader)
		if len(authSubmatches) < 2 {
			helpMsg := "invalid Authorization header value"
			ssas.SetCtxEntry(r, "Event", "AuthorizationFailure")
			logger.Error(helpMsg)
			next.ServeHTTP(w, r)
			return
		}

		tokenString := authSubmatches[1]
		token, err := server.VerifyToken(tokenString)
		if err != nil {
			helpMsg := fmt.Sprintf("unable to decode authorization header value; %s", err)
			ssas.SetCtxEntry(r, "Event", "AuthorizationFailure")
			logger.Error(helpMsg)
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
		ctx := context.WithValue(r.Context(), "ts", tokenString) //nolint:staticcheck
		ctx = context.WithValue(ctx, "rd", rd)                   //nolint:staticcheck
		ssas.SetCtxEntry(r, "rd", rd)
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

		ctx, logger := ssas.SetCtxEntry(r, "op", "tokenauth")

		tsObj := r.Context().Value("ts")
		if tsObj == nil {
			logger.Error("no token string found")
			respond(w, http.StatusUnauthorized)
			return
		}
		ts, ok = tsObj.(string)
		if !ok {
			logger.Error("token string invalid")
			respond(w, http.StatusUnauthorized)
			return
		}

		err := tokenValidity(ctx, ts, tokenType)
		if err != nil {
			logger.Error("token invalid")
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

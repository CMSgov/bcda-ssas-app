package admin

import (
	"net/http"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

func requireBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok {
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
			return
		}

		system, err := ssas.GetSystemByClientID(clientID)
		if err != nil {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client id")
			return
		}

		savedSecret, err := system.GetSecret()
		if err != nil || !ssas.Hash(savedSecret.Hash).IsHashOf(secret) {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client secret")
			return
		}

		if savedSecret.IsExpired() {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "credentials expired")
			return
		}

		next.ServeHTTP(w, r)
	})
}

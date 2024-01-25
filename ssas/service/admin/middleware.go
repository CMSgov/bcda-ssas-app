package admin

import (
	"net/http"

	"github.com/CMSgov/bcda-ssas-app/log"
	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

func requireBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		logger := log.GetCtxLogger(r.Context())

		if !ok {
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "", logger)
			return
		}

		system, err := ssas.GetSystemByClientID(r.Context(), clientID)
		if err != nil {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client id", logger)
			return
		}

		savedSecret, err := system.GetSecret(r.Context())
		if err != nil || !ssas.Hash(savedSecret.Hash).IsHashOf(secret) {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client secret", logger)
			return
		}

		if savedSecret.IsExpired() {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "credentials expired", logger)
			return
		}

		next.ServeHTTP(w, r)
	})
}

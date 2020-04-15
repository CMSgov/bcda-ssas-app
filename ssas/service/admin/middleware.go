package admin

import (
	"fmt"
	"net/http"

	"github.com/CMSgov/bcda-ssas-app/ssas"
)

func requireBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok {
			formatError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
			return
		}

		system, err := ssas.GetSystemByClientID(clientID)
		if err != nil {
			formatError(w, http.StatusUnauthorized, "invalid client id")
			return
		}

		savedSecret, err := system.GetSecret()
		if err != nil || !ssas.Hash(savedSecret.Hash).IsHashOf(secret) {
			formatError(w, http.StatusUnauthorized, "invalid client secret")
			return
		}

		if savedSecret.IsExpired() {
			formatError(w, http.StatusUnauthorized, "credentials expired")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func formatError(w http.ResponseWriter, errorcode int, description string) {
	ssas.Logger.Printf("%s; %s", description, http.StatusText(errorcode))
	w.WriteHeader(errorcode)
	body := []byte(fmt.Sprintf(`{"error":"%s","error_description":"%s"}`, http.StatusText(errorcode), description))
	_, err := w.Write(body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

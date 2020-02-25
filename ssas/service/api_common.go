package service

import (
	"encoding/json"
	"fmt"
	"github.com/CMSgov/bcda-ssas-app/ssas"
	"net/http"
)

func JsonError(w http.ResponseWriter, errorStatus int, errorText string, description string) {
	fallbackMessage := fmt.Sprintf(`{"error": "%s", "error_description": "%s"}`, http.StatusText(http.StatusInternalServerError), http.StatusText(http.StatusInternalServerError))
	e := ssas.ErrorResponse{Error: errorText, ErrorDescription: description}
	body, err := json.Marshal(e)
	if err != nil {
		http.Error(w, fallbackMessage, http.StatusInternalServerError)
	}
	ssas.Logger.Printf("%s; %s", description, errorText)
	w.WriteHeader(errorStatus)
	_, err = w.Write([]byte(body))
	if err != nil {
		http.Error(w, fallbackMessage, http.StatusInternalServerError)
	}
}

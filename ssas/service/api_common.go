package service

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/CMSgov/bcda-ssas-app/ssas"
)

func WriteHTTPSError(w http.ResponseWriter, e ssas.ErrorResponse, errorStatus int) {
	fallbackMessage := fmt.Sprintf(`{"error": "%s", "error_description": "%s"}`, http.StatusText(http.StatusInternalServerError), http.StatusText(http.StatusInternalServerError))
	body, err := json.Marshal(e)

	if err != nil {
		http.Error(w, fallbackMessage, http.StatusInternalServerError)
	}

	w.WriteHeader(errorStatus)
	_, err = w.Write(body)

	if err != nil {
		http.Error(w, fallbackMessage, http.StatusInternalServerError)
	}
}

// Follow RFC 7591 format for input errors
func JSONError(w http.ResponseWriter, errorStatus int, statusText string, statusDescription string) {
	e := ssas.ErrorResponse{Error: statusText, ErrorDescription: statusDescription}

	WriteHTTPSError(w, e, errorStatus)

	ssas.Logger.Printf("%s; %s", statusText, statusDescription) // TODO: log information about the request
}

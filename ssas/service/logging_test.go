package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareTransactionCtx(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trans := r.Context().Value(CtxTransactionKey).(string)
		if trans == "" {
			t.Error("no transaction id in context")
		}
	})

	handlerToTest := GetTransactionID(nextHandler)
	req := httptest.NewRequest("GET", "http://testing", nil)
	handlerToTest.ServeHTTP(httptest.NewRecorder(), req)

}

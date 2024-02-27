package service

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/sirupsen/logrus"

	"github.com/CMSgov/bcda-ssas-app/ssas"
)

//https://github.com/go-chi/chi/blob/master/_examples/logging/main.go

func NewAPILogger() func(next http.Handler) http.Handler {
	return middleware.RequestLogger(&APILogger{ssas.Logger})
}

type APILogger struct {
	Logger logrus.FieldLogger
}

func (l *APILogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	entry := &ssas.APILoggerEntry{Logger: l.Logger}
	logFields := logrus.Fields{}

	logFields["ts"] = time.Now() // .UTC().Format(time.RFC1123)

	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		logFields["request_id"] = reqID
	}

	scheme := "http"
	logFields["http_scheme"] = scheme
	logFields["http_proto"] = r.Proto
	logFields["http_method"] = r.Method

	logFields["remote_addr"] = r.RemoteAddr
	logFields["user_agent"] = r.UserAgent()

	logFields["uri"] = fmt.Sprintf("%s://%s%s", scheme, r.Host, Redact(r.RequestURI))

	if rd, ok := r.Context().Value("rd").(ssas.AuthRegData); ok {
		logFields["group_id"] = rd.GroupID
		logFields["okta_id"] = rd.OktaID
	}

	if tid, ok := r.Context().Value(CtxTransactionKey).(string); ok {
		logFields["transaction_id"] = tid
	}

	entry.Logger = entry.Logger.WithFields(logFields)

	entry.Logger.Infoln("request started")

	return entry
}

func Redact(uri string) string {
	re := regexp.MustCompile(`Bearer%20([^&]+)(?:&|$)`)
	submatches := re.FindAllStringSubmatch(uri, -1)
	for _, match := range submatches {
		uri = strings.Replace(uri, match[1], "<redacted>", 1)
	}
	return uri
}

// NewCtxLogger adds new key value pair of {CtxLoggerKey: logrus.FieldLogger} to the requests context
func NewCtxLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logFields := logrus.Fields{}
		logFields["request_id"] = middleware.GetReqID(r.Context())
		if rd, ok := r.Context().Value("rd").(ssas.AuthRegData); ok {
			logFields["okta_id"] = rd.OktaID
		}
		if tid, ok := r.Context().Value(CtxTransactionKey).(string); ok {
			logFields["transaction_id"] = tid
		}
		newLogEntry := &ssas.APILoggerEntry{Logger: ssas.Logger.WithFields(logFields)}
		r = r.WithContext(context.WithValue(r.Context(), ssas.CtxLoggerKey, newLogEntry))
		next.ServeHTTP(w, r)
	})
}

// type to create context.Context key
type CtxTransactionKeyType string

// context.Context key to get the transaction ID from the request context
const CtxTransactionKey CtxTransactionKeyType = "ctxTransaction"

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
	entry := &APILoggerEntry{Logger: l.Logger}
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

	entry.Logger = entry.Logger.WithFields(logFields)

	entry.Logger.Infoln("request started")

	return entry
}

type APILoggerEntry struct {
	Logger logrus.FieldLogger
}

func (l *APILoggerEntry) Write(status int, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"resp_status": status, "resp_bytes_length": bytes,
		"resp_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0,
	})

	l.Logger.Infoln("request complete")
}

func (l *APILoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
}

func Redact(uri string) string {
	re := regexp.MustCompile(`Bearer%20([^&]+)(?:&|$)`)
	submatches := re.FindAllStringSubmatch(uri, -1)
	for _, match := range submatches {
		uri = strings.Replace(uri, match[1], "<redacted>", 1)
	}
	return uri
}

func GetLogEntry(r *http.Request) logrus.FieldLogger {
	entry := middleware.GetLogEntry(r).(*APILoggerEntry)
	return entry.Logger
}

func LogEntrySetField(r *http.Request, key string, value interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*APILoggerEntry); ok {
		entry.Logger = entry.Logger.WithField(key, value)
	}
}

func LogEntrySetFields(r *http.Request, fields map[string]interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*APILoggerEntry); ok {
		entry.Logger = entry.Logger.WithFields(fields)
	}
}

// type to create context.Contest key
type CtxLoggerKeyType string

// logrus.FieldLogger value within request context
const CtxLoggerKey CtxLoggerKeyType = "ctxLogger"

type StructuredLoggerEntry struct {
	Logger logrus.FieldLogger
}

// NewCtxLogger adds new key value pair of {CtxLoggerKey: logrus.FieldLogger} to the requests context
func NewCtxLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logFields := logrus.Fields{}
		logFields["request_id"] = middleware.GetReqID(r.Context())
		if rd, ok := r.Context().Value("rd").(ssas.AuthRegData); ok {
			logFields["okta_id"] = rd.OktaID
		}
		newLogEntry := &StructuredLoggerEntry{Logger: ssas.Logger.WithFields(logFields)}
		r = r.WithContext(context.WithValue(r.Context(), CtxLoggerKey, newLogEntry))
		next.ServeHTTP(w, r)
	})
}

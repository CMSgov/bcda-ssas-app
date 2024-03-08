package ssas

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sirupsen/logrus"
)

// Logger provides a structured logger for this service
var Logger logrus.FieldLogger

// Event contains the superset of fields that may be included in Logger statements
type Event struct {
	UserID     string
	ClientID   string
	Elapsed    time.Duration
	Help       string
	Op         string
	TokenID    string
	TrackingID string
}

func init() {

	logInstance := logrus.New()
	logInstance.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	filePath, success := os.LookupEnv("SSAS_LOG")
	if success {
		/* #nosec -- 0664 permissions required for Splunk ingestion */
		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)

		if err == nil {
			logInstance.SetOutput(file)
		} else {
			logInstance.Info("Failed to open SSAS log file; using default stderr")
		}
	} else {
		logInstance.Info("No SSAS log location provided; using default stderr")
	}

	Logger = logInstance.WithFields(logrus.Fields{
		"application": constants.Application,
		"environment": os.Getenv("DEPLOYMENT_TARGET"),
		"version":     constants.Version})

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

// type to create context.Context key
type CtxLoggerKeyType string

const CtxLoggerKey CtxLoggerKeyType = "ctxLogger"

// context.Context key to set/get logrus.FieldLogger value within request context

// Gets the logrus.FieldLogger from a context
func GetCtxLogger(ctx context.Context) logrus.FieldLogger {
	logger := Logger
	if entry, ok := ctx.Value(CtxLoggerKey).(*APILoggerEntry); ok {
		logger = entry.Logger
	}
	return logger
}

// Gets the logrus.APILoggerEntry from a context
func GetCtxEntry(ctx context.Context) *APILoggerEntry {
	entry := ctx.Value(CtxLoggerKey).(*APILoggerEntry)
	return entry
}

// Appends additional logrus.Field to a logrus.FieldLogger within a context
func SetCtxEntry(r *http.Request, key string, value interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*APILoggerEntry); ok {
		entry.Logger = entry.Logger.WithField(key, value)
	}
}

var AuthorizationFailure = logrus.WithField("Event", "AuthorizationFailure")

var OperationCalled = logrus.WithField("Event", "OperationCalled")

var OperationStarted = logrus.WithField("Event", "OperationStarted")

var OperationFailed = logrus.WithField("Event", "OperationFailed")

var OperationSucceeded = logrus.WithField("Event", "OperationSucceeded")

var AccessTokenIssued = logrus.WithField("Event", "AccessTokenIssued")

/*
	The following logging functions should be passed an Event{} with at least the Op and TrackingID set, and
	other general messages put in the Help field.  Successive logs for the same event should use the same
	randomly generated TrackingID.
*/

// SecureHashTime should be called with the time taken to create a hash, logs of which can be used
// to approximate the security provided by the hash
func SecureHashTime(data Event) {
	mergeNonEmpty(data).WithField("Event", "SecureHashTime").Print(data.Help)
}

// SecretCreated should be called every time a system's secret is generated
func SecretCreated(data Event) {
	mergeNonEmpty(data).WithField("Event", "SecretCreated").Print(data.Help)
}

// ClientTokenCreated should be called every time a system  client token is generated
func ClientTokenCreated(data Event) {
	mergeNonEmpty(data).WithField("Event", "ClientTokenCreated").Print(data.Help)
}

// ServiceHalted should be called to log an unexpected stop to the service
func ServiceHalted(data Event) {
	mergeNonEmpty(data).WithField("Event", "ServiceHalted").Print(data.Help)
}

// ServiceStarted should be called to log the starting of the service
func ServiceStarted(data Event) {
	mergeNonEmpty(data).WithField("Event", "ServiceStarted").Print(data.Help)
}

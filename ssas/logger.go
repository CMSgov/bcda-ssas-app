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
	entry := ctx.Value(CtxLoggerKey).(*APILoggerEntry)
	return entry.Logger
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

func mergeNonEmpty(data Event) logrus.FieldLogger {
	entry := &APILoggerEntry{Logger: Logger}

	if data.UserID != "" {
		entry.Logger = entry.Logger.WithField("userID", data.UserID)
	}
	if data.ClientID != "" {
		entry.Logger = entry.Logger.WithField("clientID", data.ClientID)
	}
	if data.TrackingID != "" {
		entry.Logger = entry.Logger.WithField("trackingID", data.TrackingID)
	}
	if data.Elapsed != 0 {
		entry.Logger = entry.Logger.WithField("elapsed", data.Elapsed)
	}
	if data.Op != "" {
		entry.Logger = entry.Logger.WithField("op", data.Op)
	}
	if data.TokenID != "" {
		entry.Logger = entry.Logger.WithField("tokenID", data.TokenID)
	}

	return entry.Logger
}

/*
	The following logging functions should be passed an Event{} with at least the Op and TrackingID set, and
	other general messages put in the Help field.  Successive logs for the same event should use the same
	randomly generated TrackingID.
*/

// OperationStarted should be called at the beginning of all logged events
func OperationStarted(data Event) {
	mergeNonEmpty(data).WithField("Event", "OperationStarted").Print(data.Help)
}

// OperationSucceeded should be called after an event's success, and should always be preceded by
// a call to OperationStarted
func OperationSucceeded(data Event) {
	mergeNonEmpty(data).WithField("Event", "OperationSucceeded").Print(data.Help)
}

// OperationCalled will log the caller of an operation.  The caller should use the same
// randomly generated TrackingID as used in the operation for OperationStarted, OperationSucceeded, etc.
func OperationCalled(data Event) {
	mergeNonEmpty(data).WithField("Event", "OperationCalled").Print(data.Help)
}

// OperationFailed should be called after an event's failure, and should always be preceded by
// a call to OperationStarted
func OperationFailed(data Event) {
	// *TODO: refactor. Remove OperationFailed to prevent duplicate logging. Address areas affected by removal.
	mergeNonEmpty(data).WithField("Event", "OperationFailed").Print(data.Help)
}

// TokenMintingFailure is emitted when a token can't be created. Usually, this is due to a
// issue with the signing key.
func TokenMintingFailure(data Event) {
	mergeNonEmpty(data).WithField("Event", "TokenMintingFailure").Print(data.Help)
}

// AccessTokenIssued should be called to log the successful creation of every access token
func AccessTokenIssued(data Event) {
	mergeNonEmpty(data).WithField("Event", "AccessTokenIssued").Print(data.Help)
}

// TokenBlacklisted records that a token with a specific key is invalidated
func TokenBlacklisted(data Event) {
	mergeNonEmpty(data).WithField("Event", "TokenBlacklisted").Print(data.Help)
}

// BlacklistedTokenPresented logs an attempt to verify a blacklisted token
func BlacklistedTokenPresented(data Event) {
	mergeNonEmpty(data).WithField("Event", "BlacklistedTokenPresented").Print(data.Help)
}

// CacheSyncFailure is called when an in-memory cache cannot be refreshed from the database
func CacheSyncFailure(data Event) {
	mergeNonEmpty(data).WithField("Event", "CacheSyncFailure").Print(data.Help)
}

// AuthorizationFailure should be called by middleware to record token or credential issues
func AuthorizationFailure(data Event) {
	mergeNonEmpty(data).WithField("Event", "AuthorizationFailure").Print(data.Help)
}

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

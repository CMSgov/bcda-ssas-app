package ssas

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/sirupsen/logrus"
)

// Logger provides a structured logger for this service
var Logger logrus.FieldLogger = defaultLogger()

func SetupLogger() {
	logInstance := logrus.New()
	logInstance.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	if os.Getenv("LOG_TO_STD_OUT") != "true" {
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
	}

	Logger = logInstance.WithFields(logrus.Fields{
		"application": constants.Application,
		"environment": os.Getenv("DEPLOYMENT_TARGET"),
		"log_type":    "ssas",
		"version":     constants.Version,
	})
}

func defaultLogger() logrus.FieldLogger {
	logInstance := logrus.New()
	logInstance.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})

	return logInstance.WithFields(logrus.Fields{
		"application": constants.Application,
		"environment": os.Getenv("DEPLOYMENT_TARGET"),
		"log_type":    "ssas",
		"version":     constants.Version,
	})
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
	entry := ctx.Value(CtxLoggerKey)
	if entry != nil {
		return entry.(*APILoggerEntry).Logger
	}
	return Logger
}

// Gets the logrus.APILoggerEntry from a context
func GetCtxEntry(ctx context.Context) *APILoggerEntry {
	entry := ctx.Value(CtxLoggerKey).(*APILoggerEntry)
	return entry
}

// Appends additional or creates new logrus.Fields to a logrus.FieldLogger within a context
func SetCtxEntry(r *http.Request, key string, value interface{}) (context.Context, logrus.FieldLogger) {
	ctx := r.Context()
	if entry, ok := ctx.Value(CtxLoggerKey).(*APILoggerEntry); ok {
		entry.Logger = entry.Logger.WithField(key, value)
		nCtx := context.WithValue(ctx, CtxLoggerKey, entry)
		return nCtx, entry.Logger
	}

	var lggr logrus.Logger
	newLogEntry := &APILoggerEntry{Logger: lggr.WithField(key, value)}
	nCtx := context.WithValue(ctx, CtxLoggerKey, newLogEntry)
	return nCtx, newLogEntry.Logger
}

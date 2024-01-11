package ssas

import (
	"os"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
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

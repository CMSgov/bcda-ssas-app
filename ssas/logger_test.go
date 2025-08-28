package ssas

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestSetupLogger(t *testing.T) {
	env := uuid.New()
	oldEnvVal := os.Getenv("DEPLOYMENT_TARGET")
	os.Setenv("DEPLOYMENT_TARGET", env)
	oldLogVal := os.Getenv("LOG_TO_STD_OUT")
	os.Unsetenv("LOG_TO_STD_OUT")
	t.Cleanup(func() {
		os.Setenv("DEPLOYMENT_TARGET", oldEnvVal)
		os.Setenv("LOG_TO_STD_OUT", oldLogVal)
	})

	logFile, err := os.CreateTemp("", "*")
	assert.NoError(t, err)

	old := os.Getenv("SSAS_LOG")
	os.Setenv("SSAS_LOG", logFile.Name())
	t.Cleanup(func() {
		assert.NoError(t, os.Remove(logFile.Name()))
		assert.NoError(t, os.Setenv("SSAS_LOG", old))
	})

	SetupLogger()

	msg := uuid.New()
	Logger.Info(msg)

	data, err := io.ReadAll(logFile)
	assert.NoError(t, err)

	logText := strings.Split(string(data), "\n")
	assert.Len(t, logText, 2) // msg + new line

	var fields logrus.Fields
	assert.NoError(t, json.Unmarshal([]byte(logText[0]), &fields))
	assert.Equal(t, constants.Application, fields["application"])
	assert.Equal(t, env, fields["environment"])
	assert.Equal(t, msg, fields["msg"])
	assert.Equal(t, constants.Version, fields["version"])
	_, err = time.Parse(time.RFC3339Nano, fields["time"].(string))
	assert.NoError(t, err)
}

func TestSetupLogger_ToSTDOut(t *testing.T) {
	env := uuid.New()
	oldEnvVal := os.Getenv("DEPLOYMENT_TARGET")
	os.Setenv("DEPLOYMENT_TARGET", env)
	oldLogVal := os.Getenv("LOG_TO_STD_OUT")
	os.Unsetenv("LOG_TO_STD_OUT")
	t.Cleanup(func() {
		os.Setenv("DEPLOYMENT_TARGET", oldEnvVal)
		os.Setenv("LOG_TO_STD_OUT", oldLogVal)
	})

	SetupLogger()
	testLogger := test.NewLocal(getLogger(Logger))

	msg := uuid.New()
	Logger.Info(msg)

	assert.Equal(t, 1, len(testLogger.Entries))
	assert.Equal(t, msg, testLogger.LastEntry().Message)
	assert.Equal(t, "ssas", testLogger.LastEntry().Data["log_type"])
	testLogger.Reset()
}

func TestDefaultLogger(t *testing.T) {
	Logger := defaultLogger()
	testLogger := test.NewLocal(getLogger(Logger))

	msg := uuid.New()
	Logger.Info(msg)

	assert.Equal(t, 1, len(testLogger.Entries))
	assert.Equal(t, msg, testLogger.LastEntry().Message)
	assert.Equal(t, constants.Application, testLogger.LastEntry().Data["application"])
	assert.Equal(t, os.Getenv("DEPLOYMENT_TARGET"), testLogger.LastEntry().Data["environment"])
	assert.Equal(t, "ssas", testLogger.LastEntry().Data["log_type"])
	assert.Equal(t, constants.Version, testLogger.LastEntry().Data["version"])
}

// GetLogger returns the underlying implementation of the field logger
func getLogger(logger logrus.FieldLogger) *logrus.Logger {
	if entry, ok := logger.(*logrus.Entry); ok {
		return entry.Logger
	}
	// Must be a *logrus.Logger
	return logger.(*logrus.Logger)
}

package service

import (
	"testing"

	"github.com/CMSgov/bcda-ssas-app/log"
	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestOperationLogging(t *testing.T) {
	testLogger := test.NewLocal(ssas.GetLogger(log.Logger))
	event := logrus.Fields{"Op": "TestOperation", "Help": "A little more to the right"}
	testLogger.LastEntry().WithField("Event", "OperationStarted").Info(event)

	assert.Equal(t, 1, len(testLogger.Entries))
	assert.Equal(t, logrus.InfoLevel, testLogger.LastEntry().Level)
	assert.Equal(t, "A little more to the right", testLogger.LastEntry().Message)
	testLogger.Reset()
	assert.Nil(t, testLogger.LastEntry())
}

package monitoring

import (
	"fmt"
	"net/http"
	"os"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/newrelic/go-agent/v3/newrelic"
)

var a *apm

type apm struct {
	App *newrelic.Application
}

func GetMonitor() *apm {
	if a == nil {
		target := os.Getenv("DEPLOYMENT_TARGET")
		if target == "" {
			target = "local"
		}
		app, err := newrelic.NewApplication(
			newrelic.ConfigAppName(fmt.Sprintf("BCDA-SSAS-%s", target)),
			newrelic.ConfigLicense(os.Getenv("NEW_RELIC_LICENSE_KEY")),
			newrelic.ConfigEnabled(true),
			newrelic.ConfigDistributedTracerEnabled(true),
			func(cfg *newrelic.Config) {
				cfg.HighSecurity = true
			},
		)
		if err != nil {
			ssas.Logger.Error(err)
		}
		a = &apm{
			App: app,
		}
	}
	return a
}

func (a apm) WrapHandler(pattern string, h http.HandlerFunc) (string, func(http.ResponseWriter, *http.Request)) {
	if a.App != nil {
		return newrelic.WrapHandleFunc(a.App, pattern, h)
	}
	return pattern, h
}

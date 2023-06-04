package monitoring

import (
	"fmt"
	"net/http"

	"github.com/CMSgov/bcda-sass-app/sass/cfg"
	"github.com/CMSgov/bcda-app/log"

	"github.com/newrelic/go-agent/v3/newrelic"
)

var a *apm

type apm struct {
	App *newrelic.Application
}

func GetMonitor() *apm {
	if a == nil {
		target := conf.GetEnv("DEPLOYMENT_TARGET")
		if target == "" {
			target = "local"
		}
		app, err := newrelic.NewApplication(
			newrelic.ConfigAppName(fmt.Sprintf("BCDA-%s", target)),
			newrelic.ConfigLicense(conf.GetEnv("NEW_RELIC_LICENSE_KEY")),
			newrelic.ConfigEnabled(true),
			newrelic.ConfigDistributedTracerEnabled(true),
			func(cfg *newrelic.Config) {
				cfg.HighSecurity = true
			},
		)
		if err != nil {
			log.API.Error(err)
		}
		a = &apm{
			App: app,
		}
	}
	return a
}
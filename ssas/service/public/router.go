package public

import (
	"fmt"
	"os"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/monitoring"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	gcmw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"

)

var server *service.Server

func Server() *service.Server {
	unsafeMode := os.Getenv("HTTP_ONLY") == "true"
	useMTLS := os.Getenv("PUBLIC_USE_MTLS") == "true"
	publicSigningKeyPath := os.Getenv("SSAS_PUBLIC_SIGNING_KEY_PATH")
	publicSigningKey := os.Getenv("SSAS_PUBLIC_SIGNING_KEY")
	ssas.Logger.Info("public signing key sourced from ", publicSigningKeyPath)
	clientAssertAud := os.Getenv("SSAS_CLIENT_ASSERTION_AUD")
	ssas.Logger.Info("aud value required in client assertion tokens:", clientAssertAud)

	signingKey, err := service.ChooseSigningKey(publicSigningKeyPath, publicSigningKey)
	if err != nil {
		msg := fmt.Sprintf("Unable to get public server signing key: %v", err)
		ssas.Logger.Error(msg)
		return nil
	}

	server = service.NewServer("public", ":3003", routes(), unsafeMode, useMTLS, signingKey, 20*time.Minute, clientAssertAud)


	return server
}

func routes(db *gorm.DB) *chi.Mux {
	router := chi.NewRouter()
	m := monitoring.GetMonitor()

	h := NewPublicHandler(db, AccessTokenCreator{})
	mh := NewPublicMiddlewareHandler(db)

	router.Use(
		gcmw.RequestID,
		service.GetTransactionID,
		service.NewAPILogger(),
		service.ConnectionClose,
		service.NewCtxLogger,
		SkipSGAAuthCheck,
	)

	// public routes
	router.With(render.SetContentType((render.ContentTypeJSON))).Get("/_version", h.getVersion)
	router.With(render.SetContentType((render.ContentTypeJSON))).Get("/_health", h.getHealthCheck)
	router.With(render.SetContentType((render.ContentTypeJSON))).Get("/_info", h.getInfo)

	// v1 Routes
	router.Post(m.WrapHandler("/token", h.token))
	router.Post(m.WrapHandler("/introspect", h.introspect))
	router.With(mh.parseToken, mh.requireRegTokenAuth, mh.readGroupID).Post(m.WrapHandler("/register", h.RegisterSystem))
	router.With(mh.parseToken, mh.requireRegTokenAuth, mh.readGroupID).Post(m.WrapHandler("/reset", h.ResetSecret))

	// v2 Routes
	router.Post(m.WrapHandler("/v2/token", h.tokenV2))
	router.Post(m.WrapHandler("/v2/token_info", h.validateAndParseToken))

	return router
}

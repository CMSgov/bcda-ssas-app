package public

import (
	"fmt"
	"os"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/monitoring"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	gcmw "github.com/go-chi/chi/v5/middleware"
)

var server *service.Server

func Server() *service.Server {
	unsafeMode := os.Getenv("HTTP_ONLY") == "true"
	useMTLS := os.Getenv("PUBLIC_USE_MTLS") == "true"
	infoMap := make(map[string][]string)
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

	server = service.NewServer("public", ":3003", constants.Version, infoMap, routes(), unsafeMode, useMTLS, signingKey, 20*time.Minute, clientAssertAud)
	if server != nil {
		r, _ := server.ListRoutes()
		infoMap["banner"] = []string{fmt.Sprintf("%s server running on port %s", "public", ":3003")}
		infoMap["routes"] = r
	}
	return server
}

func routes() *chi.Mux {
	router := chi.NewRouter()
	m := monitoring.GetMonitor()
	db, err := ssas.CreateDB()
	if err != nil {
		panic(fmt.Sprintf("failed to connect to database: %s", err))
	}
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

	//v1 Routes
	router.Post(m.WrapHandler("/token", h.token))
	router.Post(m.WrapHandler("/introspect", h.introspect))
	router.With(mh.parseToken, mh.requireRegTokenAuth, mh.readGroupID).Post(m.WrapHandler("/register", h.RegisterSystem))
	router.With(mh.parseToken, mh.requireRegTokenAuth, mh.readGroupID).Post(m.WrapHandler("/reset", h.ResetSecret))

	//v2 Routes
	router.Post(m.WrapHandler("/v2/token", h.tokenV2))
	router.Post(m.WrapHandler("/v2/token_info", h.validateAndParseToken))

	return router
}

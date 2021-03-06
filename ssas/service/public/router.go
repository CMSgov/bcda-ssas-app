package public

import (
	"fmt"
	"os"
	"time"

	"github.com/go-chi/chi"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

var infoMap map[string][]string
var publicSigningKeyPath string
var server *service.Server

func init() {
	infoMap = make(map[string][]string)
	publicSigningKeyPath = os.Getenv("SSAS_PUBLIC_SIGNING_KEY_PATH")
	ssas.Logger.Info("public signing key sourced from ", publicSigningKeyPath)
}

func Server() *service.Server {
	unsafeMode := os.Getenv("HTTP_ONLY") == "true"
	server = service.NewServer("public", ":3003", constants.Version, infoMap, routes(), unsafeMode, publicSigningKeyPath, 20*time.Minute)
	if server != nil {
		r, _ := server.ListRoutes()
		infoMap["banner"] = []string{fmt.Sprintf("%s server running on port %s", "public", ":3003")}
		infoMap["routes"] = r
	}
	return server
}

func routes() *chi.Mux {
	router := chi.NewRouter()
	router.Use(service.NewAPILogger(), service.ConnectionClose)
	router.Post("/token", token)
	router.Post("/introspect", introspect)
	router.Post("/authn", VerifyPassword)
	router.With(parseToken, requireMFATokenAuth).Post("/authn/challenge", RequestMultifactorChallenge)
	router.With(parseToken, requireMFATokenAuth).Post("/authn/verify", VerifyMultifactorResponse)
	router.With(parseToken, requireRegTokenAuth, readGroupID).Post("/register", RegisterSystem)
	router.With(parseToken, requireRegTokenAuth, readGroupID).Post("/reset", ResetSecret)

	return router
}

package admin

import (
	"fmt"
	"github.com/CMSgov/bcda-ssas-app/ssas"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

var infoMap map[string][]string
var adminSigningKeyPath string
var server *service.Server

func init() {
	infoMap = make(map[string][]string)
	adminSigningKeyPath = os.Getenv("SSAS_ADMIN_SIGNING_KEY_PATH")
}

// Server creates an SSAS admin server
func Server() *service.Server {
	unsafeMode := os.Getenv("HTTP_ONLY") == "true"
	server = service.NewServer("admin", ":3004", constants.Version, infoMap, routes(), unsafeMode, adminSigningKeyPath, 20*time.Minute)
	if server != nil {
		r, _ := server.ListRoutes()
		infoMap["banner"] = []string{fmt.Sprintf("%s server running on port %s", "admin", ":3004")}
		infoMap["routes"] = r
	}
	return server
}

func routes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(service.NewAPILogger(), service.ConnectionClose)
	r.With(requireAdminAuth).Post("/group", createGroup)
	r.With(requireAdminAuth).Get("/group", listGroups)
	r.With(requireAdminAuth).Put("/group/{id}", updateGroup)
	r.With(requireAdminAuth).Delete("/group/{id}", deleteGroup)
	r.With(requireAdminAuth).Post("/system", createSystem)
	r.With(requireAdminAuth).Put("/system/{systemID}/credentials", resetCredentials)
	r.With(requireAdminAuth).Get("/system/{systemID}/key", getPublicKey)
	r.With(requireAdminAuth).Delete("/system/{systemID}/credentials", deactivateSystemCredentials)
	r.With(requireAdminAuth).Delete("/token/{tokenID}", revokeToken)
	r.With(requireAdminAuth).Get("/system/ips", listIPs)

	swaggerPath := "./swaggerui"
	if _, err := os.Stat(swaggerPath); os.IsNotExist(err) {
		ssas.Logger.Info("swagger path not found: " + swaggerPath)
		swaggerPath = "../swaggerui"
	} else {
		ssas.Logger.Info("swagger path found: " + swaggerPath)
	}
	FileServer(r, "/swagger", http.Dir(swaggerPath))

	return r
}

// FileServer conveniently sets up a http.FileServer handler to serve
// static files from a http.FileSystem.
// stolen from https://github.com/go-chi/chi/blob/master/_examples/fileserver/main.go
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit URL parameters.")
	}

	fs := http.StripPrefix(path, http.FileServer(root))

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

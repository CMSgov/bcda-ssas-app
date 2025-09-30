package admin

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/monitoring"

	"github.com/go-chi/chi/v5"
	gcmw "github.com/go-chi/chi/v5/middleware"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

// Server creates an SSAS admin server
func Server() *service.Server {
	unsafeMode := os.Getenv("HTTP_ONLY") == "true"
	useMTLS := os.Getenv("ADMIN_USE_MTLS") == "true"
	adminSigningKeyPath := os.Getenv("SSAS_ADMIN_SIGNING_KEY_PATH")
	adminSigningKey := os.Getenv("SSAS_ADMIN_SIGNING_KEY")

	infoMap := make(map[string][]string)

	signingKey, err := service.ChooseSigningKey(adminSigningKeyPath, adminSigningKey)
	if err != nil {
		msg := fmt.Sprintf("Unable to get admin server signing key %v", err)
		ssas.Logger.Error(msg)
		return nil
	}

	server := service.NewServer("admin", ":3004", constants.Version, infoMap, routes(), unsafeMode, useMTLS, signingKey, 20*time.Minute, "")
	if server != nil {
		r, _ := server.ListRoutes()
		infoMap["banner"] = []string{fmt.Sprintf("%s server running on port %s", "admin", ":3004")}
		infoMap["routes"] = r
	}
	return server
}

func routes() *chi.Mux {
	r := chi.NewRouter()
	m := monitoring.GetMonitor()
	h := NewAdminHandler()
	mh := NewAdminMiddlewareHandler()

	r.Use(gcmw.RequestID, service.GetTransactionID, service.NewAPILogger(), service.ConnectionClose, service.NewCtxLogger)

	r.With(mh.requireBasicAuth).Post(m.WrapHandler("/group", h.createGroup))
	r.With(mh.requireBasicAuth).Get(m.WrapHandler("/group", h.listGroups))
	r.With(mh.requireBasicAuth).Put(m.WrapHandler("/group/{id}", h.updateGroup))
	r.With(mh.requireBasicAuth).Delete(m.WrapHandler("/group/{id}", h.deleteGroup))
	r.With(mh.requireBasicAuth).Post(m.WrapHandler("/system", h.createSystem))
	r.With(mh.requireBasicAuth).Put(m.WrapHandler("/system/{systemID}/credentials", h.resetCredentials))
	r.With(mh.requireBasicAuth).Get(m.WrapHandler("/system/{systemID}/key", h.getPublicKey))
	r.With(mh.requireBasicAuth).Delete(m.WrapHandler("/system/{systemID}/credentials", h.deactivateSystemCredentials))
	r.With(mh.requireBasicAuth).Delete(m.WrapHandler("/token/{tokenID}", h.revokeToken))

	r.Route("/v2", func(r chi.Router) {
		r.With(mh.requireBasicAuth).Post(m.WrapHandler("/system", h.createV2System))
		r.With(mh.requireBasicAuth).Post(m.WrapHandler("/group", h.createGroup))
		r.With(mh.requireBasicAuth).Get(m.WrapHandler("/group", h.listGroups))
		r.With(mh.requireBasicAuth).Patch(m.WrapHandler("/group/{id}", h.updateGroup))
		r.With(mh.requireBasicAuth).Patch(m.WrapHandler("/system/{id}", h.updateSystem))
		r.With(mh.requireBasicAuth).Get(m.WrapHandler("/system/{id}", h.getSystem))
		r.With(mh.requireBasicAuth).Post(m.WrapHandler("/system/{systemID}/ip", h.registerIP))
		r.With(mh.requireBasicAuth).Get(m.WrapHandler("/system/{systemID}/ip", h.getSystemIPs))
		r.With(mh.requireBasicAuth).Delete(m.WrapHandler("/system/{systemID}/ip/{id}", h.deleteSystemIP))
		r.With(mh.requireBasicAuth).Post(m.WrapHandler("/system/{systemID}/token", h.createToken))
		r.With(mh.requireBasicAuth).Delete(m.WrapHandler("/system/{systemID}/token/{id}", h.deleteToken))
		r.With(mh.requireBasicAuth).Post(m.WrapHandler("/system/{systemID}/key", h.createKey))
		r.With(mh.requireBasicAuth).Delete(m.WrapHandler("/system/{systemID}/key/{id}", h.deleteKey))
	})

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
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	}))
}

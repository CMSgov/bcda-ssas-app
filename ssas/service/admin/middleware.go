package admin

import (
	"context"
	"net/http"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"gorm.io/gorm"
)

type adminMiddlewareHandler struct {
	db *gorm.DB
	sr *ssas.SystemRepository
	gr *ssas.GroupRepository
}

func NewAdminMiddlewareHandler(db *gorm.DB) *adminMiddlewareHandler {
	return &adminMiddlewareHandler{
		sr: ssas.NewSystemRepository(db),
		gr: ssas.NewGroupRepository(db),
		db: db,
	}
}

func (h *adminMiddlewareHandler) requireBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, secret, ok := r.BasicAuth()
		if !ok {
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
			return
		}

		system, err := h.sr.GetSystemByClientID(r.Context(), clientID)
		if err != nil {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client id")
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), constants.CtxSGAKey, system.SGAKey))

		// skip auth checks if requester is us
		if system.SGAKey == "bcda" {
			r = r.WithContext(context.WithValue(r.Context(), constants.CtxSGASkipAuthKey, "true"))
		}

		savedSecret, err := h.sr.GetSecret(r.Context(), system)
		if err != nil || !ssas.Hash(savedSecret.Hash).IsHashOf(secret) {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client secret")
			return
		}

		if savedSecret.IsExpired() {
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "credentials expired")
			return
		}

		next.ServeHTTP(w, r)
	})
}

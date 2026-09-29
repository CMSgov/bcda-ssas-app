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
	sr ssas.SystemRepository
	gr ssas.GroupRepository
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
		ssas.SetCtxEntry(r, "Op", "CreateGroup")
		logger := ssas.GetCtxLogger(r.Context())

		clientID, secret, ok := r.BasicAuth()
		if !ok {
			logger.Error("failed to get basic auth creds")
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
			return
		}

		system, err := h.sr.GetSystemByClientID(r.Context(), clientID)
		if err != nil {
			logger.Errorf("failed to get system by client ID %s, err: %v", clientID, err)
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
			logger.Warningf("failed to validate client secret for client ID %s, err: %v", clientID, err)
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client secret")
			return
		}

		if savedSecret.IsExpired() {
			logger.Warningf("client secret for client ID %s has expired", clientID)
			service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "credentials expired")
			return
		}

		next.ServeHTTP(w, r)
	})
}

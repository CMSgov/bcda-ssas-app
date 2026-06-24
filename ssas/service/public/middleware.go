package public

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type publicMiddlewareHandler struct {
	db                   *gorm.DB
	sr                   ssas.SystemRepository
	gr                   ssas.GroupRepository
	clientIDToACOIDCache *cache.Cache
	rateLimitCache       *cache.Cache
}

func NewPublicMiddlewareHandler(db *gorm.DB) *publicMiddlewareHandler {
	duration := time.Duration(cfg.RateLimitDurationMinutes) * time.Minute
	return &publicMiddlewareHandler{
		sr:                   ssas.NewSystemRepository(db),
		gr:                   ssas.NewGroupRepository(db),
		db:                   db,
		clientIDToACOIDCache: cache.New(20*time.Minute, 5*time.Minute),
		rateLimitCache:       cache.New(duration, 1*time.Minute),
	}
}

func (h *publicMiddlewareHandler) readGroupID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			rd  ssas.AuthRegData
			err error
		)

		logger := ssas.GetCtxLogger(r.Context())

		if rd, err = readRegData(r); err != nil {
			logger.Println("no data from token about allowed groups")
			respond(w, http.StatusUnauthorized)
			return
		}

		if rd.GroupID = r.Header.Get("x-group-id"); rd.GroupID == "" {
			logger.Println("missing header x-group-id")
			respond(w, http.StatusUnauthorized)
			return
		}

		if !contains(rd.AllowedGroupIDs, rd.GroupID) {
			logger.Println("group specified in x-group-id not in token's allowed groups")
			respond(w, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "rd", rd) //nolint:staticcheck
		ssas.SetCtxEntry(r, "rd", rd)

		sgaKey, err := ssas.GetSGAKeyByGroupID(r.Context(), h.db, rd.GroupID)
		if err == nil {
			r = r.WithContext(context.WithValue(r.Context(), constants.CtxSGAKey, sgaKey))
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Puts the decoded token, identity, and authorization values into the request context. Decoded values have been
// verified to be tokens signed by our server and to have not expired. Additional authorization
// occurs in requireRegTokenAuth() or requireMFATokenAuth().
func (h *publicMiddlewareHandler) parseToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := logrus.Fields{"Op": "ParseToken"}
		logger := ssas.GetCtxLogger(r.Context()).WithFields(event)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			helpMsg := "no authorization header found"
			ssas.SetCtxEntry(r, "Event", "AuthorizationFailure")
			logger.Error(helpMsg)
			next.ServeHTTP(w, r)
			return
		}

		authRegexp := regexp.MustCompile(`^Bearer (\S+)$`)
		authSubmatches := authRegexp.FindStringSubmatch(authHeader)
		if len(authSubmatches) < 2 {
			helpMsg := "invalid Authorization header value"
			ssas.SetCtxEntry(r, "Event", "AuthorizationFailure")
			logger.Error(helpMsg)
			next.ServeHTTP(w, r)
			return
		}

		tokenString := authSubmatches[1]
		token, err := server.VerifyToken(tokenString)
		if err != nil {
			helpMsg := fmt.Sprintf("unable to decode authorization header value; %s", err)
			ssas.SetCtxEntry(r, "Event", "AuthorizationFailure")
			logger.Error(helpMsg)
			next.ServeHTTP(w, r)
			return
		}

		var rd ssas.AuthRegData
		if rd, err = readRegData(r); err != nil {
			rd = ssas.AuthRegData{}
		}

		if claims, ok := token.Claims.(*service.CommonClaims); ok && token.Valid {
			rd.AllowedGroupIDs = claims.GroupIDs
			rd.OktaID = claims.OktaID
		}
		ctx := context.WithValue(r.Context(), "ts", tokenString) //nolint:staticcheck
		ctx = context.WithValue(ctx, "rd", rd)                   //nolint:staticcheck
		ssas.SetCtxEntry(r, "rd", rd)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *publicMiddlewareHandler) requireRegTokenAuth(next http.Handler) http.Handler {
	return h.tokenAuth(next, "RegistrationToken")
}

func (h *publicMiddlewareHandler) requireMFATokenAuth(next http.Handler) http.Handler {
	return h.tokenAuth(next, "MFAToken")
}

func (h *publicMiddlewareHandler) tokenAuth(next http.Handler, tokenType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ts string
			ok bool
		)

		ctx, logger := ssas.SetCtxEntry(r, "op", "tokenauth")

		tsObj := r.Context().Value("ts")
		if tsObj == nil {
			logger.Error("no token string found")
			respond(w, http.StatusUnauthorized)
			return
		}
		ts, ok = tsObj.(string)
		if !ok {
			logger.Error("token string invalid")
			respond(w, http.StatusUnauthorized)
			return
		}

		err := tokenValidity(ctx, ts, tokenType)
		if err != nil {
			logger.Error("token invalid")
			respond(w, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SkipSGAAuthCheck allows requests to skip SGA auth checks, be careful when adding new requests with this middleware!
// This is needed as certain public requests use some ORM functions that require auth checks.
func SkipSGAAuthCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), constants.CtxSGASkipAuthKey, "true"))

		next.ServeHTTP(w, r)
	})
}

func respond(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

const invalidACOIDSentinel = "__INVALID_ACO_ID__"

func (h *publicMiddlewareHandler) TokenRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := ssas.GetCtxLogger(r.Context()).WithField("Op", "TokenRateLimit")

		clientID, _, ok := r.BasicAuth()
		if !ok || clientID == "" {
			// Basic auth not present, let the actual auth handler handle and reject the request
			next.ServeHTTP(w, r)
			return
		}

		// Retrieve ACO ID (with caching)
		var acoID string
		if cached, found := h.clientIDToACOIDCache.Get(clientID); found {
			acoID = cached.(string)
			if acoID == invalidACOIDSentinel {
				// Pass through directly to normal auth handler
				next.ServeHTTP(w, r)
				return
			}
		} else {
			// Query DB via SystemRepository
			system, err := h.sr.GetSystemByClientID(r.Context(), clientID)
			if err != nil {
				// Cache the lookup failure (negative caching) for 1 minute
				h.clientIDToACOIDCache.Set(clientID, invalidACOIDSentinel, time.Minute)
				// If system doesn't exist, just pass through and let Validate/Authenticate handle it
				next.ServeHTTP(w, r)
				return
			}

			// Parse ACO ID from Group's XData
			acoID, err = ssas.GetACOIDFromSystem(r.Context(), system, h.gr)
			if err != nil {
				// Cache the lookup failure (negative caching) for 1 minute
				h.clientIDToACOIDCache.Set(clientID, invalidACOIDSentinel, time.Minute)
				// If we can't extract the ACO ID, log it and pass through
				logger.Warnf("Failed to extract ACO ID for client %s: %s", clientID, err.Error())
				next.ServeHTTP(w, r)
				return
			}

			// Store in cache
			h.clientIDToACOIDCache.Set(clientID, acoID, cache.DefaultExpiration)
		}

		// Rate limit check
		duration := time.Duration(cfg.RateLimitDurationMinutes) * time.Minute

		// We use IncrementInt to atomically increment the counter.
		// If key doesn't exist (returns error), we attempt to Add it with value 1 atomically.
		newVal, err := h.rateLimitCache.IncrementInt(acoID, 1)
		if err != nil {
			// Key not found in cache (first request in window). Initialize to 1 atomically.
			if err = h.rateLimitCache.Add(acoID, 1, duration); err == nil {
				newVal = 1
			} else {
				// Another concurrent request added it in the meantime, retry incrementing.
				newVal, err = h.rateLimitCache.IncrementInt(acoID, 1)
				if err != nil {
					// Fallback warning if something went wrong
					logger.Warnf("Failed to increment rate limit counter for ACO %s: %s", acoID, err.Error())
					newVal = 1
				}
			}
		}

		if newVal > cfg.RateLimitThreshold {
			logger.Warnf("Rate limit exceeded for ACO %s (Client %s): %d requests in %v", acoID, clientID, newVal, duration)
			retryAfterSeconds := strconv.Itoa(cfg.RateLimitDurationMinutes * 60)
			w.Header().Set("Retry-After", retryAfterSeconds)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

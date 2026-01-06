/*
Package public (ssas/service/api/public) contains API functions, middleware, and a router designed to:
 1. Be accessible to the public
 2. Offer system self-registration and self-management
*/
package public

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pborman/uuid"
	"gorm.io/gorm"
)

type publicHandler struct {
	db *gorm.DB
	sr *ssas.GormSystemRepository
	gr *ssas.GormGroupRepository
	tc TokenCreator
}

func NewPublicHandler(db *gorm.DB, tc TokenCreator) *publicHandler {
	return &publicHandler{
		sr: ssas.NewSystemRepository(db),
		gr: ssas.NewGroupRepository(db),
		tc: tc,
		db: db,
	}
}

type Key struct {
	E   string `json:"e"`
	N   string `json:"n"`
	KTY string `json:"kty"`
	Use string `json:"use,omitempty"`
}

type JWKS struct {
	Keys []Key `json:"keys"`
}

type RegistrationRequest struct {
	ClientID    string   `json:"client_id"`
	ClientName  string   `json:"client_name"`
	Scope       string   `json:"scope,omitempty"`
	JSONWebKeys JWKS     `json:"jwks"`
	IPs         []string `json:"ips"`
}

type ResetRequest struct {
	ClientID string `json:"client_id"`
}

type SystemResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ExpiresAt    int64  `json:"client_secret_expires_at"`
	ClientName   string `json:"client_name"`
}

type TokenResponse struct {
	Scope       string `json:"scope,omitempty"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   string `json:"expires_in"`
}

/*
ResetSecret is mounted at POST /reset and allows the authenticated manager of a system to rotate their secret.
*/
func (h *publicHandler) ResetSecret(w http.ResponseWriter, r *http.Request) {
	var (
		rd          ssas.AuthRegData
		err         error
		req         ResetRequest
		sys         ssas.System
		bodyStr     []byte
		credentials ssas.Credentials
		//event       ssas.Event
	)
	setHeaders(w)

	logger := ssas.GetCtxLogger(r.Context())

	if rd, err = readRegData(r); err != nil || rd.GroupID == "" {
		logger.Error("missing or invalid GroupID")
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}

	if bodyStr, err = io.ReadAll(r.Body); err != nil {
		logger.Error("invalid_client_metadata: request body cannot be read")
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be read")
		return
	}

	if err = json.Unmarshal(bodyStr, &req); err != nil {
		ssas.SetCtxEntry(r, "bodyStr", bodyStr)
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be parsed")
		return
	}

	if sys, err = h.sr.GetSystemByClientID(r.Context(), req.ClientID); err != nil {
		logger.Error("failed to get retrieve system by client id: client not found")
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusNotFound), "client not found")
		return
	}

	if !contains(rd.AllowedGroupIDs, rd.GroupID) || sys.GroupID != rd.GroupID {
		logger.Error("group id not allowed or does not match system group id")
		service.JSONError(w, http.StatusUnauthorized, "invalid_client_metadata", "Invalid group")
		return
	}

	ssas.SetCtxEntry(r, "Op", "ResetSecret")
	logger.Info("Operation Called: public.ResetSecret()")
	if credentials, err = h.sr.ResetSecret(r.Context(), sys); err != nil {
		logger.Error("failed to reset secret")
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	response := SystemResponse{
		ClientID:     credentials.ClientID,
		ClientSecret: credentials.ClientSecret,
		ExpiresAt:    credentials.ExpiresAt.Unix(),
		ClientName:   credentials.ClientName,
	}
	body, err := json.Marshal(response)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
	if _, err = w.Write(body); err != nil {
		logger.Error("failure writing response body: " + err.Error())
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
}

/*
		RegisterSystem is mounted at POST /auth/register and allows for self-registration.  It requires that a
		registration token containing one or more group ids be presented and parsed by middleware, with the
	    GroupID[s] placed in the context key "rd".
*/
func (h *publicHandler) RegisterSystem(w http.ResponseWriter, r *http.Request) {
	var (
		rd             ssas.AuthRegData
		err            error
		reg            RegistrationRequest
		publicKeyBytes []byte
		publicKeyPEM   string
		trackingID     string
	)

	setHeaders(w)
	logger := ssas.GetCtxLogger(r.Context())

	if rd, err = readRegData(r); err != nil || rd.GroupID == "" {
		logger.Error("missing or invalid GroupID")
		// Specified in RFC 7592 https://tools.ietf.org/html/rfc7592#page-6
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}

	bodyStr, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error("invalid_client_metadata: request body cannot be read")
		// Response types and format specified in RFC 7591 https://tools.ietf.org/html/rfc7591#section-3.2.2
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be read")
		return
	}

	err = json.Unmarshal(bodyStr, &reg)
	if err != nil {
		logger.Error("invalid_client_metadata: request body cannot be parsed")
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be parsed")
		return
	}

	if reg.JSONWebKeys.Keys != nil {
		if len(reg.JSONWebKeys.Keys) > 1 {
			logger.Error("invalid_client_metadata: Exactly one JWK must be presented")
			service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Exactly one JWK must be presented")
			return
		}

		publicKeyBytes, err = json.Marshal(reg.JSONWebKeys.Keys[0])
		if err != nil {
			logger.Error("failed to marshal JSON: ", err)
			service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Unable to read JWK")
			return
		}

		publicKeyPEM, err = ssas.ConvertJWKToPEM(string(publicKeyBytes))
		if err != nil {
			logger.Error("invalid_client_metadata: Unable to process JWK")
			service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Unable to process JWK")
			return
		}
	}

	// Log the source of the call for this operation.  Remaining logging will be in ssas.RegisterSystem() below.
	ssas.SetCtxEntry(r, "Op", "RegisterSystem")
	logger.Info("Operation Called: public.RegisterSystem()")
	credentials, err := h.sr.RegisterSystem(r.Context(), reg.ClientName, rd.GroupID, reg.Scope, publicKeyPEM, reg.IPs, trackingID)
	if err != nil {
		logger.Error("failed to register system")
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "")
		return
	}

	response := SystemResponse{
		ClientID:     credentials.ClientID,
		ClientSecret: credentials.ClientSecret,
		ExpiresAt:    credentials.ExpiresAt.Unix(),
		ClientName:   credentials.ClientName,
	}
	body, err := json.Marshal(response)
	if err != nil {
		logger.WithField("resp_status", http.StatusInternalServerError).Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
	// https://tools.ietf.org/html/rfc7591#section-3.2 dictates 201, not 200
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(body)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
}

func readRegData(r *http.Request) (data ssas.AuthRegData, err error) {
	var ok bool
	data, ok = r.Context().Value("rd").(ssas.AuthRegData)
	if !ok {
		err = errors.New("no registration data in context")
	}
	return
}

func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (h *publicHandler) token(w http.ResponseWriter, r *http.Request) {
	logger := ssas.GetCtxLogger(r.Context())

	clientID, secret, ok := r.BasicAuth()
	if !ok {
		logger.Error("basic auth failed")
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	system, err := h.sr.GetSystemByClientID(r.Context(), clientID)
	if err != nil {
		logger.Errorf("The client id %s is invalid", err.Error())
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client id")
		return
	}
	err = h.ValidateSecret(system, secret, r)
	if err != nil {
		logger.Error("The client id and secret cannot be validated: ", err.Error())
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), err.Error())
		return
	}

	data, err := h.gr.XDataFor(r.Context(), system)
	logger.Infof("public.api.token: XDataFor(%d) returned '%s'", system.ID, data)
	if err != nil {
		logger.Error("no group for system: ", err.Error())
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "no group for system")
		return
	}

	ssas.SetCtxEntry(r, "Op", "token")
	logger.Info("Calling Operation: public.token()")

	claims := CreateCommonClaims("AccessToken", "", fmt.Sprintf("%d", system.ID), system.ClientID, data, "", nil)

	token, ts, err := h.tc.GenerateToken(claims)
	if err != nil {
		logger.Error("failure minting token")
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "failure minting token")
		return
	}

	err = h.sr.SaveTokenTime(r.Context(), system)
	if err != nil {
		logger.Error("failed to save token time for ", system.ClientID)
	}
	logger.Info("token created in group %s with XData: %s", system.GroupID, data)

	// https://tools.ietf.org/html/rfc6749#section-5.1
	// expires_in is duration in seconds
	expiresIn := token.Claims.(*service.CommonClaims).ExpiresAt.Sub(token.Claims.(*service.CommonClaims).IssuedAt.Time)
	m := TokenResponse{AccessToken: ts, TokenType: "bearer", ExpiresIn: strconv.FormatFloat(expiresIn.Seconds(), 'f', 0, 64)}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	render.JSON(w, r, m)
}

func (h *publicHandler) ValidateSecret(system ssas.System, secret string, r *http.Request) (err error) {
	savedSecret, err := h.sr.GetSecret(r.Context(), system)
	if !ssas.Hash(savedSecret.Hash).IsHashOf(secret) {
		return errors.New(constants.InvalidClientSecret)
	}

	if savedSecret.IsExpired() {
		return errors.New("the saved client credendials are expired")
	}
	return err
}

func (h *publicHandler) tokenV2(w http.ResponseWriter, r *http.Request) {
	trackingID := uuid.NewRandom().String()
	ssas.SetCtxEntry(r, "Op", "token")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Info("Operation Called: public.tokenV2()")
	valError := validateClientAssertionParams(r)
	if valError != "" {
		logger.Error(valError)
		service.JSONError(w, http.StatusBadRequest, valError, "")
		return
	}

	tokenString := r.Form.Get("client_assertion")
	token, err := parseClientSignedToken(r.Context(), tokenString, trackingID)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	claims := token.Claims.(*service.CommonClaims)
	if claims.Subject != claims.Issuer {
		service.JSONError(w, http.StatusBadRequest, "subject (sub) and issuer (iss) claims do not match", "")
		return
	}

	if claims.ID == "" {
		service.JSONError(w, http.StatusBadRequest, "missing Token ID (jti) claim", "")
		return
	}

	if !slices.Contains(claims.Audience, server.GetClientAssertionAudience()) {
		service.JSONError(w, http.StatusBadRequest, "invalid audience (aud) claim", "")
		return
	}

	tokenDuration := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if tokenDuration.Seconds() > 300 { // 5 minute max duration
		service.JSONError(w, http.StatusBadRequest, "IssuedAt (iat) and ExpiresAt (exp) claims are more than 5 minutes apart", "")
		return
	}

	if tokenDuration.Seconds() < 0 { // issued at AFTER expires at
		service.JSONError(w, http.StatusBadRequest, "IssuedAt (iat) claim marked as AFTER ExpiresAt (exp) claim", "")
		return
	}

	systemID, err := server.GetSystemIDFromMacaroon(claims.Issuer)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, "Macaroon does not contain system id", "")
		return
	}

	system, err := h.sr.GetSystemByID(r.Context(), systemID)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid issuer (iss) claim. system not found")
		return
	}

	data, err := h.gr.XDataFor(r.Context(), system)
	logger.Infof("public.api.token: XDataFor(%d) returned '%s'", system.ID, data)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "no group for system")
		return
	}

	commonClaims := CreateCommonClaims("AccessToken", "", fmt.Sprintf("%d", system.ID), system.ClientID, data, system.XData, nil)

	accessToken, ts, err := h.tc.GenerateToken(commonClaims)
	if err != nil {
		logger.Error(err)
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}

	err = h.sr.SaveTokenTime(r.Context(), system)
	if err != nil {
		logger.Error(err)
	}

	// https://tools.ietf.org/html/rfc6749#section-5.1
	// expires_in is duration in seconds
	expiresIn := accessToken.Claims.(*service.CommonClaims).ExpiresAt.Sub(accessToken.Claims.(*service.CommonClaims).IssuedAt.Time)
	m := TokenResponse{Scope: "system/*.*", AccessToken: ts, TokenType: "bearer", ExpiresIn: strconv.FormatFloat(expiresIn.Seconds(), 'f', 0, 64)}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	render.JSON(w, r, m)
}

func validateClientAssertionParams(r *http.Request) string {
	if err := r.ParseForm(); err != nil {
		return "unable to parse form data"
	}
	contentTypeHeader := r.Header.Get("Content-Type")
	if contentTypeHeader == "" {
		return "missing Content-Type header"
	}

	if contentTypeHeader != "application/x-www-form-urlencoded" {
		return "invalid Content Type Header value. Supported Types: [application/x-www-form-urlencoded]"
	}

	if r.Header.Get("Accept") != "application/json" {
		return "invalid Accept header value. Supported types: [application/json]"
	}

	if r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return "invalid value for client_assertion_type"
	}

	if r.Form.Get("grant_type") != "client_credentials" {
		return "invalid value for grant_type"
	}

	if r.Form.Get("scope") != "system/*.*" {
		return "invalid scope value"
	}

	if r.Form.Get("client_assertion") == "" {
		return "missing client_assertion"
	}
	return ""
}

func parseClientSignedToken(ctx context.Context, jwt string, trackingID string) (*jwt.Token, error) {
	return server.VerifyClientSignedToken(ctx, jwt, trackingID)
}

func (h *publicHandler) introspect(w http.ResponseWriter, r *http.Request) {
	logger := ssas.GetCtxLogger(r.Context())

	clientID, secret, ok := r.BasicAuth()

	if !ok {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid auth header")
		return
	}

	if clientID == "" || secret == "" {
		msg := "empty value in clientID and/or secret"
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), msg)
		return
	}

	system, err := h.sr.GetSystemByClientID(r.Context(), clientID)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), fmt.Sprintf("invalid client id; %s", err))
		return
	}

	savedSecret, err := h.sr.GetSecret(r.Context(), system)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), fmt.Sprintf("can't get secret; %s", err))
		return
	}

	if !ssas.Hash(savedSecret.Hash).IsHashOf(secret) {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client secret")
		return
	}

	defer r.Body.Close()

	var reqV map[string]string
	if err = json.NewDecoder(r.Body).Decode(&reqV); err != nil {
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid body")
		return
	}
	var answer = make(map[string]bool)
	answer["active"] = true
	if err = tokenValidity(r.Context(), reqV["token"], "AccessToken"); err != nil {
		logger.Infof("token failed tokenValidity, err: %+v", err)
		answer["active"] = false
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	render.JSON(w, r, answer)
}

func (h *publicHandler) validateAndParseToken(w http.ResponseWriter, r *http.Request) {
	logger := ssas.GetCtxLogger(r.Context())
	defer r.Body.Close()

	var reqV map[string]string
	if err := json.NewDecoder(r.Body).Decode(&reqV); err != nil {
		logger.Error("failed to decode json: ", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid request body")
		return
	}
	tokenS := reqV["token"]
	if tokenS == "" {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), `missing "token" field in body`)
		return
	}
	var response = make(map[string]interface{})

	if err := tokenValidity(r.Context(), tokenS, "AccessToken"); err != nil {
		logger.Infof("token failed tokenValidity")
		response["valid"] = false
	} else {
		claims := jwt.MapClaims{}
		if _, _, err := new(jwt.Parser).ParseUnverified(tokenS, claims); err != nil {
			logger.Error("could not unmarshal access token")
			service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "internal server error")
			return
		}
		response["valid"] = true
		response["data"] = claims["dat"]
		response["system_data"] = claims["system_data"]
		sys, err := h.sr.GetSystemByID(r.Context(), claims["sys"].(string))
		if err != nil {
			logger.Error("could not get system id")
			service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "internal server error")
			return
		}
		response["scope"] = sys.APIScope
	}
	w.Header().Set("Content-Type", "application/json")
	render.JSON(w, r, response)
}

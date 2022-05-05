/*
	Package public (ssas/service/api/public) contains API functions, middleware, and a router designed to:
		1. Be accessible to the public
		2. Offer system self-registration and self-management
*/
package public

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pborman/uuid"
)

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

type MFARequest struct {
	LoginID     string  `json:"login_id"`
	FactorType  string  `json:"factor_type"`
	Passcode    *string `json:"passcode,omitempty"`
	Transaction *string `json:"transaction,omitempty"`
}

type PasswordRequest struct {
	LoginID  string `json:"login_id"`
	Password string `json:"password"`
}

type SystemResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ExpiresAt    int64  `json:"client_secret_expires_at"`
	ClientName   string `json:"client_name"`
}

type VerifyMFAResponse struct {
	FactorResult      string `json:"factor_result"`
	RegistrationToken string `json:"registration_token,omitempty"`
	AvailableGroups   string `json:"available_groups,omitempty"`
}

/*
	VerifyPassword is mounted at POST /authn and responds with the account status for a verified username/password
 	combination.
*/
func VerifyPassword(w http.ResponseWriter, r *http.Request) {
	var (
		err        error
		trackingID string
		passReq    PasswordRequest
	)

	setHeaders(w)

	bodyStr, err := ioutil.ReadAll(r.Body)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be read")
		return
	}

	err = json.Unmarshal(bodyStr, &passReq)
	if err != nil {
		service.LogEntrySetField(r, "bodyStr", "<redacted>")
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be parsed")
		return
	}

	trackingID = uuid.NewRandom().String()
	event := ssas.Event{Op: "VerifyOktaPassword", TrackingID: trackingID, Help: "calling from public.VerifyPassword()"}
	ssas.OperationCalled(event)
	passwordResponse, oktaId, err := GetProvider().VerifyPassword(passReq.LoginID, passReq.Password, trackingID)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	if passwordResponse.Success {
		_, passwordResponse.Token, err = MintMFAToken(oktaId)
	}
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure generating JSON: " + err.Error()
		ssas.OperationFailed(event)
		return
	}

	body, err := json.Marshal(passwordResponse)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure generating JSON: " + err.Error()
		ssas.OperationFailed(event)
		return
	}

	_, err = w.Write(body)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure writing response body: " + err.Error()
		ssas.OperationFailed(event)
		return
	}
}

/*
	RequestMultifactorChallenge is mounted at POST /authn/challenge and sends a multi-factor authentication request
	using the specified factor.

	Valid factor types include:
		"Google TOTP" (Google Authenticator)
		"Okta TOTP"   (Okta Verify app time-based token)
		"Push"        (Okta Verify app push)
		"SMS"
		"Call"
		"Email"

	In the case of the Push factor, a transaction ID is returned to use with the polling endpoint:
	    POST /authn/verify/transactions/{transaction_id}
*/
func RequestMultifactorChallenge(w http.ResponseWriter, r *http.Request) {
	var (
		err        error
		trackingID string
		mfaReq     MFARequest
	)

	setHeaders(w)

	bodyStr, err := ioutil.ReadAll(r.Body)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be read")
		return
	}

	err = json.Unmarshal(bodyStr, &mfaReq)
	if err != nil {
		service.LogEntrySetField(r, "bodyStr", bodyStr)
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be parsed")
		return
	}

	trackingID = uuid.NewRandom().String()
	event := ssas.Event{Op: "RequestOktaFactorChallenge", TrackingID: trackingID, Help: "calling from public.RequestMultifactorChallenge()"}
	ssas.OperationCalled(event)
	factorResponse, err := GetProvider().RequestFactorChallenge(mfaReq.LoginID, mfaReq.FactorType, trackingID)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	body, err := json.Marshal(factorResponse)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure generating JSON: " + err.Error()
		ssas.OperationFailed(event)
		return
	}

	_, err = w.Write(body)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure writing response body: " + err.Error()
		ssas.OperationFailed(event)
		return
	}
}

/*
	VerifyMultifactorResponse is mounted at POST /authn/verify and tests a multi-factor authentication passcode
	for the specified factor, and should be used for all factor types except Push.
*/
func VerifyMultifactorResponse(w http.ResponseWriter, r *http.Request) {
	var (
		err        error
		trackingID string
		mfaReq     MFARequest
		body       []byte
		ts         string
		groupIDs   []string
	)

	setHeaders(w)

	bodyStr, err := ioutil.ReadAll(r.Body)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be read")
		return
	}

	err = json.Unmarshal(bodyStr, &mfaReq)
	if err != nil {
		service.LogEntrySetField(r, "bodyStr", bodyStr)
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be parsed")
		return
	}

	if mfaReq.Passcode == nil {
		service.LogEntrySetField(r, "bodyStr", bodyStr)
		service.JSONError(w, http.StatusUnauthorized, "invalid_client_metadata", "Request body missing passcode")
		return
	}

	trackingID = uuid.NewRandom().String()
	event := ssas.Event{Op: "VerifyOktaFactorResponse", TrackingID: trackingID, Help: "calling from public.VerifyMultifactorResponse()"}
	ssas.OperationCalled(event)
	success, oktaID, groupIDs := GetProvider().VerifyFactorChallenge(mfaReq.LoginID, mfaReq.FactorType, *mfaReq.Passcode, trackingID)

	if !success {
		event.Help = "passcode rejected"
		ssas.OperationFailed(event)

		_, err = w.Write([]byte(`{"factor_result":"failure"}`))
		if err != nil {
			service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
			event.Help = "failure writing response body: " + err.Error()
			ssas.OperationFailed(event)
			return
		}
	}

	if empty(groupIDs) {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "no authorized groups"
		ssas.OperationFailed(event)
		return
	}

	gIdsBytes, err := json.Marshal(groupIDs)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "no authorized groups: " + err.Error()
		ssas.OperationFailed(event)
		return
	}

	event.Help = "passcode accepted"
	ssas.OperationSucceeded(event)
	if _, ts, err = MintRegistrationToken(oktaID, groupIDs); err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure creating registration token: " + err.Error()
		ssas.OperationFailed(event)
		return
	}

	response := VerifyMFAResponse{
		FactorResult:      "success",
		RegistrationToken: ts,
		AvailableGroups:   string(gIdsBytes),
	}
	body, err = json.Marshal(response)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure marshaling JSON for verifyMultifactorResponse: " + err.Error()
		ssas.OperationFailed(event)
		return
	}
	_, err = w.Write(body)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure writing response body: " + err.Error()
		ssas.OperationFailed(event)
		return
	}
}

/*
	ResetSecret is mounted at POST /reset and allows the authenticated manager of a system to rotate their secret.
*/
func ResetSecret(w http.ResponseWriter, r *http.Request) {
	var (
		rd          ssas.AuthRegData
		err         error
		trackingID  string
		req         ResetRequest
		sys         ssas.System
		bodyStr     []byte
		credentials ssas.Credentials
		event       ssas.Event
	)
	setHeaders(w)

	if rd, err = readRegData(r); err != nil || rd.GroupID == "" {
		service.GetLogEntry(r).Println("missing or invalid GroupID")
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}

	if bodyStr, err = ioutil.ReadAll(r.Body); err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be read")
		return
	}

	if err = json.Unmarshal(bodyStr, &req); err != nil {
		service.LogEntrySetField(r, "bodyStr", bodyStr)
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be parsed")
		return
	}

	if sys, err = ssas.GetSystemByClientID(req.ClientID); err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Client not found")
		return
	}

	if !contains(rd.AllowedGroupIDs, rd.GroupID) || sys.GroupID != rd.GroupID {
		service.JSONError(w, http.StatusUnauthorized, "invalid_client_metadata", "Invalid group")
		return
	}

	event = ssas.Event{Op: "ResetSecret", TrackingID: uuid.NewRandom().String(), Help: "calling from public.ResetSecret()"}
	ssas.OperationCalled(event)
	if credentials, err = sys.ResetSecret(trackingID); err != nil {
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
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure generating JSON for credential reset: " + err.Error()
		ssas.OperationFailed(event)
		return
	}
	if _, err = w.Write(body); err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure writing response body: " + err.Error()
		ssas.OperationFailed(event)
		return
	}
}

/*
	RegisterSystem is mounted at POST /auth/register and allows for self-registration.  It requires that a
	registration token containing one or more group ids be presented and parsed by middleware, with the
    GroupID[s] placed in the context key "rd".
*/
func RegisterSystem(w http.ResponseWriter, r *http.Request) {
	var (
		rd             ssas.AuthRegData
		err            error
		reg            RegistrationRequest
		publicKeyBytes []byte
		publicKeyPEM   string
		trackingID     string
	)

	setHeaders(w)

	if rd, err = readRegData(r); err != nil || rd.GroupID == "" {
		service.GetLogEntry(r).Println("missing or invalid GroupID")
		// Specified in RFC 7592 https://tools.ietf.org/html/rfc7592#page-6
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}

	bodyStr, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// Response types and format specified in RFC 7591 https://tools.ietf.org/html/rfc7591#section-3.2.2
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be read")
		return
	}

	err = json.Unmarshal(bodyStr, &reg)
	if err != nil {
		service.LogEntrySetField(r, "bodyStr", bodyStr)
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Request body cannot be parsed")
		return
	}

	if reg.JSONWebKeys.Keys != nil {
		if len(reg.JSONWebKeys.Keys) > 1 {
			service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Exactly one JWK must be presented")
			return
		}

		publicKeyBytes, err = json.Marshal(reg.JSONWebKeys.Keys[0])
		if err != nil {
			service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Unable to read JWK")
			return
		}

		publicKeyPEM, err = ssas.ConvertJWKToPEM(string(publicKeyBytes))
		if err != nil {
			service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", "Unable to process JWK")
			return
		}
	}

	// Log the source of the call for this operation.  Remaining logging will be in ssas.RegisterSystem() below.
	trackingID = uuid.NewRandom().String()
	event := ssas.Event{Op: "RegisterClient", TrackingID: trackingID, Help: "calling from public.RegisterSystem()"}
	ssas.OperationCalled(event)
	credentials, err := ssas.RegisterSystem(reg.ClientName, rd.GroupID, reg.Scope, publicKeyPEM, reg.IPs, trackingID)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
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
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure generating JSON for system creation: " + err.Error()
		ssas.OperationFailed(event)
		return
	}
	// https://tools.ietf.org/html/rfc7591#section-3.2 dictates 201, not 200
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(body)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		event.Help = "failure writing response body: " + err.Error()
		ssas.OperationFailed(event)
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

type TokenResponse struct {
	Scope       string `json:"scope,omitempty"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   string `json:"expires_in"`
}

func token(w http.ResponseWriter, r *http.Request) {
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	system, err := ssas.GetSystemByClientID(clientID)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client id")
		return
	}

	savedSecret, err := system.GetSecret()
	if err != nil || !ssas.Hash(savedSecret.Hash).IsHashOf(secret) {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid client secret")
		return
	}

	if savedSecret.IsExpired() {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "credentials expired")
		return
	}

	trackingID := uuid.NewRandom().String()

	data, err := ssas.XDataFor(system)
	ssas.Logger.Infof("public.api.token: XDataFor(%d) returned '%s'", system.ID, data)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "no group for system")
		return
	}

	event := ssas.Event{Op: "Token", TrackingID: trackingID, Help: "calling from public.token()"}
	ssas.OperationCalled(event)
	token, ts, err := MintAccessToken(fmt.Sprintf("%d", system.ID), system.ClientID, data, "")
	if err != nil {
		event.Help = "failure minting token: " + err.Error()
		ssas.OperationFailed(event)
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}

	system.SaveTokenTime()
	event.Help = fmt.Sprintf("token created in group %s with XData: %s", system.GroupID, data)

	// https://tools.ietf.org/html/rfc6749#section-5.1
	// expires_in is duration in seconds
	expiresIn := token.Claims.(*service.CommonClaims).ExpiresAt - token.Claims.(*service.CommonClaims).IssuedAt
	m := TokenResponse{AccessToken: ts, TokenType: "bearer", ExpiresIn: strconv.FormatInt(expiresIn, 10)}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	ssas.AccessTokenIssued(event)
	ssas.OperationSucceeded(event)
	render.JSON(w, r, m)
}

func tokenV2(w http.ResponseWriter, r *http.Request) {
	trackingID := uuid.NewRandom().String()
	event := ssas.Event{Op: "V2-Token", TrackingID: trackingID, Help: "calling from public.tokenV2()"}
	ssas.OperationCalled(event)
	valError := validateClientAssertionParams(r)
	if valError != "" {
		event.Help = valError
		ssas.AuthorizationFailure(event)
		service.JSONError(w, http.StatusBadRequest, valError, "")
		return
	}

	tokenString := r.Form.Get("client_assertion")
	token, err := parseClientSignedToken(tokenString, trackingID)
	if err != nil {
		event.Help = err.Error()
		ssas.AuthorizationFailure(event)
		service.JSONError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	claims := token.Claims.(*service.CommonClaims)
	if claims.Subject != claims.Issuer {
		event.Help = "subject (sub) and issuer (iss) claims do not match"
		ssas.AuthorizationFailure(event)
		service.JSONError(w, http.StatusBadRequest, "subject (sub) and issuer (iss) claims do not match", "")
		return
	}

	if claims.Id == "" {
		event.Help = "missing Token ID (jti) claim"
		ssas.AuthorizationFailure(event)
		service.JSONError(w, http.StatusBadRequest, "missing Token ID (jti) claim", "")
		return
	}

	if claims.Audience != server.GetClientAssertionAudience() {
		event.Help = "invalid audience (aud) claim"
		ssas.AuthorizationFailure(event)
		service.JSONError(w, http.StatusBadRequest, "invalid audience (aud) claim", "")
		return
	}

	tokenDuration := claims.ExpiresAt - claims.IssuedAt
	if tokenDuration > 300 { //5 minute max duration
		event.Help = "IssuedAt (iat) and ExpiresAt (exp) claims are more than 5 minutes apart"
		ssas.AuthorizationFailure(event)
		service.JSONError(w, http.StatusBadRequest, "IssuedAt (iat) and ExpiresAt (exp) claims are more than 5 minutes apart", "")
		return
	}

	systemID, err := server.GetSystemIDFromMacaroon(claims.Issuer)
	if err != nil {
		event.Help = "Macaroon does not contain system id"
		ssas.AuthorizationFailure(event)
		service.JSONError(w, http.StatusBadRequest, "Macaroon does not contain system id", "")
		return
	}

	system, err := ssas.GetSystemByID(systemID)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "invalid issuer (iss) claim. system not found")
		return
	}

	data, err := ssas.XDataFor(system)
	ssas.Logger.Infof("public.api.token: XDataFor(%d) returned '%s'", system.ID, data)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "no group for system")
		return
	}

	accessToken, ts, err := MintAccessToken(fmt.Sprintf("%d", system.ID), system.ClientID, data, system.XData)
	if err != nil {
		event.Help = "failure minting token: " + err.Error()
		ssas.OperationFailed(event)
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "")
		return
	}

	system.SaveTokenTime()
	event.Help = fmt.Sprintf("token created in group %s with XData: %s", system.GroupID, data)

	// https://tools.ietf.org/html/rfc6749#section-5.1
	// expires_in is duration in seconds
	expiresIn := accessToken.Claims.(*service.CommonClaims).ExpiresAt - accessToken.Claims.(*service.CommonClaims).IssuedAt
	m := TokenResponse{Scope: "system/*.*", AccessToken: ts, TokenType: "bearer", ExpiresIn: strconv.FormatInt(expiresIn, 10)}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	ssas.AccessTokenIssued(event)
	ssas.OperationSucceeded(event)
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

func parseClientSignedToken(jwt string, trackingID string) (*jwt.Token, error) {
	return server.VerifyClientSignedToken(jwt, trackingID)
}

func introspect(w http.ResponseWriter, r *http.Request) {
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

	system, err := ssas.GetSystemByClientID(clientID)
	if err != nil {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), fmt.Sprintf("invalid client id; %s", err))
		return
	}

	savedSecret, err := system.GetSecret()
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
	if err = tokenValidity(reqV["token"], "AccessToken"); err != nil {
		ssas.Logger.Infof("token failed tokenValidity")
		answer["active"] = false
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	render.JSON(w, r, answer)
}

func validateAndParseToken(w http.ResponseWriter, r *http.Request) {
	trackingID := uuid.NewRandom().String()
	event := ssas.Event{Op: "V2-Token-Info", TrackingID: trackingID, Help: "calling from admin.validateAndParseToken()"}
	ssas.OperationCalled(event)

	defer r.Body.Close()

	var reqV map[string]string
	if err := json.NewDecoder(r.Body).Decode(&reqV); err != nil {
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid request body")
		return
	}
	tokenS := reqV["token"]
	if tokenS == "" {
		service.JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), `missing "token" field in body`)
		return
	}
	var response = make(map[string]interface{})

	if err := tokenValidity(tokenS, "AccessToken"); err != nil {
		ssas.Logger.Infof("token failed tokenValidity")
		response["valid"] = false
	} else {
		claims := jwt.MapClaims{}
		if _, _, err := new(jwt.Parser).ParseUnverified(tokenS, claims); err != nil {
			ssas.Logger.Infof("could not unmarshal access token")
			service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "internal server error")
			return
		}
		response["valid"] = true
		response["data"] = claims["dat"]
		response["system_data"] = claims["system_data"]
		sys, err := ssas.GetSystemByID(claims["sys"].(string))
		if err != nil {
			ssas.Logger.Infof("could not get system id")
			service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "internal server error")
			return
		}
		response["scope"] = sys.APIScope
	}
	w.Header().Set("Content-Type", "application/json")
	render.JSON(w, r, response)
}

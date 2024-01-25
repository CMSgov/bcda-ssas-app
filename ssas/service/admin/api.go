package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/log"
	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

/*
swagger:route POST /group group createGroup

# Create group

Creates a security group (which roughly corresponds to an entity such as an ACO).  Systems (which have credentials)
can be associated with this group in order to specify their scopes (rights).

Produces:
- application/json

Security:

	basic_auth:

Responses:

	201: groupResponse
	400: badRequestResponse
	401: invalidCredentials
	500: serverError
*/
func createGroup(w http.ResponseWriter, r *http.Request) {
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "CreateGroup", "TrackingID": trackingID}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	errLog := logger.WithField("Event", "OperationFailed")

	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	gd := ssas.GroupData{}
	err := json.Unmarshal(body, &gd)
	if err != nil {
		errMsg := fmt.Sprintf("error in request to create group; raw request: %v; error: %v", body, err.Error())
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "", nil)
		return
	}

	calledMsg := fmt.Sprintf("calling from admin.createGroup(), raw request: %v", string(body))
	logger.Info(logrus.Fields{"Event": "OperationCalled", "Help": calledMsg})
	g, err := ssas.CreateGroup(r.Context(), gd, trackingID)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, fmt.Sprintf("failed to create group; %s", err), "", logger)
		return
	}

	groupJSON, err := json.Marshal(g)
	if err != nil {
		errMsg := err.Error()
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(groupJSON)
	if err != nil {
		errMsg := err.Error()
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
	}
}

/*
swagger:route GET /group group listGroups

# List groups

Returns the complete list of registered security groups and their systems.

Produces:
- application/json

Security:

	basic_auth:

Responses:

	200: groupsResponse
	401: invalidCredentials
	500: serverError
*/
func listGroups(w http.ResponseWriter, r *http.Request) {
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "ListGroups", "TrackingID": trackingID, "Help": "calling from admin.listGroups()"}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	logger.Info(logrus.Fields{"Event": "OperationCalled"})
	errLog := logger.WithField("Event", "OperationFailed")

	groups, err := ssas.ListGroups(r.Context(), trackingID)
	if err != nil {
		errLog.Error(logrus.Fields{"Help": err.Error()})
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
		return
	}

	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		errLog.Error(logrus.Fields{"Help": err.Error()})
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupsJSON)
	if err != nil {
		errLog.Error(logrus.Fields{"Help": err.Error()})
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
	}
}

/*
swagger:route PUT /group/{group_id} group updateGroup

# Update group

Updates the attributes of an existing group.

Produces:
- application/json

Security:

	basic_auth:

Responses:

	200: groupResponse
	400: badRequestResponse
	401: invalidCredentials
	500: serverError
*/
func updateGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "UpdateGroup", "TrackingID": trackingID}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	errLog := logger.WithField("Event", "OperationFailed")

	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	gd := ssas.GroupData{}
	err := json.Unmarshal(body, &gd)
	if err != nil {
		errMsg := fmt.Sprintf("error in request to create group; raw request: %v; error: %v", body, err.Error())
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "", nil)
		return
	}

	calledHelp := fmt.Sprintf("calling from admin.updateGroup(), raw request: %v", string(body))
	logger.Info(logrus.Fields{"Event": "OperationCalled", "Help": calledHelp})
	g, err := ssas.UpdateGroup(r.Context(), id, gd)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("failed to update group; %s", err), logger)
		return
	}

	groupJSON, err := json.Marshal(g)
	if err != nil {
		errMsg := err.Error()
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupJSON)
	if err != nil {
		errMsg := err.Error()
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
	}
}

func getSystem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "UpdateSystem", "TrackingID": trackingID}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	errLog := logger.WithField("Event", "OperationFailed")

	s, err := ssas.GetSystemByID(r.Context(), id)
	if err != nil {
		errMsg := fmt.Sprintf("; could not find system %s", id)
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusNotFound, "", errMsg, nil)
		return
	}

	ips, _ := s.GetIPsData(r.Context())
	cts, _ := s.GetClientTokens(r.Context(), trackingID)
	eks, _ := s.GetEncryptionKeys(r.Context(), trackingID)

	o := ssas.SystemOutput{
		GID:          fmt.Sprintf("%d", s.GID),
		GroupID:      s.GroupID,
		ClientID:     s.ClientID,
		SoftwareID:   s.SoftwareID,
		ClientName:   s.ClientName,
		APIScope:     s.APIScope,
		XData:        s.XData,
		LastTokenAt:  s.LastTokenAt.Format(time.RFC3339),
		PublicKeys:   ssas.OutputPK(eks...),
		IPs:          ssas.OutputIP(ips...),
		ClientTokens: ssas.OutputCT(cts...),
	}

	systemJSON, err := json.Marshal(o)
	if err != nil {
		errLog.Error(logrus.Fields{"Help": "failed to marshal data"})
		service.JSONError(w, http.StatusInternalServerError, "failed to marshal data", "", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(systemJSON)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
	}
}

func updateSystem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "UpdateSystem", "TrackingID": trackingID}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	errLog := logger.WithField("Event", "OperationFailed")
	defer r.Body.Close()

	var v map[string]string
	err := json.NewDecoder(r.Body).Decode(&v)
	if err != nil {
		errMsg := fmt.Sprintf("error in request to update system; %v", err.Error())
		errLog.Error(logrus.Fields{"Help": errMsg})
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "", nil)
		return
	}

	calledHelp := "calling from admin.updateSystem()"
	logger.Info(logrus.Fields{"Event": "OperationCalled", "Help": calledHelp})

	//If attribute is in map, then update is allowed. if value is true, field can have an empty value.
	mutableFields := map[string]bool{"api_scope": false, "client_name": false, "software_id": true}
	for k, val := range v {
		blankAllowed, updateAllowed := mutableFields[k]
		if !updateAllowed {
			errMsg := fmt.Sprintf("error in request to update group; %v is not valid", k)
			errLog.Error(logrus.Fields{"Help": errMsg})
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("attribute: %v is not valid", k), nil)
			return
		}
		if !blankAllowed && val == "" {
			errMsg := fmt.Sprintf("error in request to update group; %v may not be empty", k)
			errLog.Error(logrus.Fields{"Help": errMsg})
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("attribute: %v may not be empty", k), nil)
			return
		}
	}

	_, err = ssas.UpdateSystem(r.Context(), id, v)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, fmt.Sprintf("failed to update system; %s", err), "", logger)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
}

/*
swagger:route DELETE /group/{group_id} group deleteGroup

# Delete group

Soft-deletes a group, invalidating any associated systems and their credentials.

Produces:
- application/json

Security:

	basic_auth:

Responses:

	200: okResponse
	400: badRequestResponse
	401: invalidCredentials
*/
func deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	logger := log.GetCtxLogger(r.Context()).WithFields(logrus.Fields{"Op": "DeleteGroup", "TrackingID": id, "Help": "calling from admin.deleteGroup()"})
	logger.Info(logrus.Fields{"Event": "OperationCalled"})
	err := ssas.DeleteGroup(r.Context(), id)
	if err != nil {
		logger.Error(logrus.Fields{"Op": "admin.deleteGroup", "Help": err.Error()})
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("failed to delete group; %s", err), nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}

/*
swagger:route POST /system system createSystem

# Create system

Creates a system, which will have credentials that can be used by an automated software system.  The system will be
associated with a security group (which roughly corresponds to an entity such as an ACO).

Produces:
- application/json

Security:

	basic_auth:

Responses:

	201: systemResponse
	400: badRequestResponse
	401: invalidCredentials
	500: serverError
*/
func createSystem(w http.ResponseWriter, r *http.Request) {
	sys := ssas.SystemInput{}
	logger := log.GetCtxLogger(r.Context())
	if err := json.NewDecoder(r.Body).Decode(&sys); err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "", logger)
		return
	}

	logger.Info(logrus.Fields{"Op": "RegisterClient", "TrackingID": sys.TrackingID, "Help": "calling from admin.createSystem()", "Event": "OperationCalled"})
	creds, err := ssas.RegisterSystem(r.Context(), sys.ClientName, sys.GroupID, sys.Scope, sys.PublicKey, sys.IPs, sys.TrackingID)

	if err != nil {
		service.JSONError(w, http.StatusBadRequest, fmt.Sprintf("could not create system; %s", err), "", logger)
		return
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
	}
}

func createV2System(w http.ResponseWriter, r *http.Request) {
	sys := ssas.SystemInput{}
	logger := log.GetCtxLogger(r.Context())
	if err := json.NewDecoder(r.Body).Decode(&sys); err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "", logger)
		return
	}

	logger.Info(logrus.Fields{"Op": "RegisterClient", "TrackingID": sys.TrackingID, "Help": "calling from admin.createSystem()", "Event": "OperationCalled"})
	creds, err := ssas.RegisterV2System(r.Context(), sys)
	if err != nil {
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("could not create v2 system; %s", err), logger)
		return
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
	}
}

/*
swagger:route PUT /system/{system_id}/credentials system resetCredentials

# Reset credentials

Rotates the credentials for the specified system.

Produces:
- application/json

Security:

	basic_auth:

Responses:

	201: systemResponse
	401: invalidCredentials
	404: notFoundResponse
	500: serverError
*/
func resetCredentials(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	logger := log.GetCtxLogger(r.Context())

	if err != nil {
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", logger)
		return
	}

	trackingID := ssas.RandomHexID()
	logger.Info(logrus.Fields{"Op": "ResetSecret", "TrackingID": trackingID, "Help": "calling from admin.resetCredentials()", "Event": "OperationCalled"})
	creds, err := system.ResetSecret(r.Context(), trackingID)

	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
		return
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
	}
}

/*
swagger:route GET /system/{system_id}/key system getPublicKey

# Get Public Key

Returns the specified system's public key, if present.

Produces:
- application/json

Security:

	basic_auth:

Responses:

	200: publicKeyResponse
	401: invalidCredentials
	404: notFoundResponse
*/
func getPublicKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	logger := log.GetCtxLogger(r.Context())
	system, err := ssas.GetSystemByID(r.Context(), systemID)

	if err != nil {
		service.JSONError(w, http.StatusNotFound, "invalid system ID", "", logger)
		return
	}

	trackingID := ssas.RandomHexID()
	logger.Info(logrus.Fields{"Op": "GetEncryptionKey", "TrackingID": trackingID, "Help": "calling from admin.getPublicKey()", "Event": "OperationCalled"})
	key, _ := system.GetEncryptionKey(r.Context(), trackingID)

	w.Header().Set("Content-Type", "application/json")
	keyStr := strings.Replace(key.Body, "\n", "\\n", -1)
	fmt.Fprintf(w, `{ "client_id": "%s", "public_key": "%s" }`, system.ClientID, keyStr)
}

/*
swagger:route DELETE /system/{system_id}/credentials system deleteCredentials

# Delete credentials

Revokes the credentials for the specified system.

Produces:
- application/json

Security:

	basic_auth:

Responses:

	200: okResponse
	401: invalidCredentials
	404: notFoundResponse
	500: serverError
*/
func deactivateSystemCredentials(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	logger := log.GetCtxLogger(r.Context())

	if err != nil {
		service.JSONError(w, http.StatusNotFound, "invalid system ID", "", logger)
		return
	}
	err = system.RevokeSecret(r.Context(), systemID)

	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "invalid system ID", "", logger)
		return
	}

	w.WriteHeader(http.StatusOK)
}

/*
	  	swagger:route DELETE /token/{token_id} token revokeToken

		Revoke token

		Revokes the specified tokenID by placing it on a blacklist.  Will return an HTTP 200 status whether or not the tokenID has been issued.

		Produces:
		- application/json

		Security:
			basic_auth:

		Responses:
			200: okResponse
			401: invalidCredentials
			500: serverError
*/
func revokeToken(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "tokenID")

	event := logrus.Fields{"Op": "TokenBlacklist", "TokenID": tokenID}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	logger.Info(logrus.Fields{"Event": "OperationCalled"})

	if err := service.TokenBlacklist.BlacklistToken(r.Context(), tokenID, service.TokenCacheLifetime); err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed", "Help": err.Error()})
		service.JSONError(w, http.StatusInternalServerError, "internal server error", "", nil)
	}

	w.WriteHeader(http.StatusOK)
}

func registerIP(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	input := IPAddressInput{}
	logger := log.GetCtxLogger(r.Context())

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "", logger)
		return
	}

	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", logger)
		return
	}

	trackingID := ssas.RandomHexID()

	if !ssas.ValidAddress(input.Address) {
		service.JSONError(w, http.StatusBadRequest, "invalid ip address", "", logger)
		return
	}

	logger.Info(logrus.Fields{"Op": "RegisterIP", "TrackingID": trackingID, "Help": "calling from admin.resetCredentials()", "Event": "OperationFailed"})
	ip, err := system.RegisterIP(r.Context(), input.Address, trackingID)
	if err != nil {
		if err.Error() == "duplicate ip address" {
			service.JSONError(w, http.StatusConflict, "duplicate ip address", "", logger)
			return
		}
		if err.Error() == "max ip address reached" {
			service.JSONError(w, http.StatusBadRequest, "max ip addresses reached", "", logger)
			return
		}
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
		return
	}

	ipJson, err := json.Marshal(ip)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(ipJson)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
	}
}

func getSystemIPs(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	logger := log.GetCtxLogger(r.Context())
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", logger)
		return
	}

	trackingID := ssas.RandomHexID()
	logger.Info(logrus.Fields{"Op": "GetSystemIPs", "TrackingID": trackingID, "Help": "calling from admin.getSystemIPs()", "Event": "OperationCalled"})
	ips, err := system.GetIps(r.Context(), trackingID)
	if err != nil {
		logger.Error("Could not retrieve system ips", err)
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
		return
	}

	ipJson, err := json.Marshal(ips)
	if err != nil {
		logger.Error("Could not marshal system ips", err)
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(ipJson)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
	}
}

/*
swagger:route DELETE /system/{system_id}/ip/{ip_id} system deleteSystemIP

# Delete IP

Soft-deletes the IP of the associated system. Returns the deleted IP.

Produces:
- application/json

Security:

	basic_auth:

Responses:

	200: okResponse
	400: badRequestResponse
	500: serverErrorResponse
	404: notFoundResponse
*/
func deleteSystemIP(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ipID := chi.URLParam(r, "id")
	trackingID := ssas.RandomHexID()
	ipEvent := logrus.Fields{"Op": "UpdateGroup", "TrackingID": trackingID, "Help": "calling from admin.deleteSystemIP()"}
	logger := log.GetCtxLogger(r.Context()).WithFields(ipEvent)

	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed"})
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", nil)
		return
	}

	logger.Info(logrus.Fields{"Event": "OperationCalled"})

	err = system.DeleteIP(r.Context(), ipID, trackingID)
	if err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed"})
		service.JSONError(w, http.StatusBadRequest, fmt.Sprintf("Failed to delete IP: %s", err), "", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func createToken(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "CreateToken", "TrackingID": trackingID, "Help": "calling from admin.createToken()"}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	errLog := logger.WithField("Event", "OperationFailed")
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		errLog.Error()
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", nil)
		return
	}

	group, err := ssas.GetGroupByGroupID(r.Context(), system.GroupID)
	if err != nil {
		errLog.Error()
		service.JSONError(w, http.StatusInternalServerError, "Internal Error", "", nil)
		return
	}

	logger.Info(logrus.Fields{"Event": "OperationCalled"})

	var body map[string]string
	b, err := io.ReadAll(r.Body)
	if err != nil {
		errLog.Error()
		service.JSONError(w, http.StatusInternalServerError, "Internal Error", "", nil)
		return
	}

	if err := json.Unmarshal(b, &body); err != nil {
		errLog.Error()
		service.JSONError(w, http.StatusInternalServerError, "Internal Error", "", nil)
		return
	}

	if body["label"] == "" {
		errLog.Error()
		service.JSONError(w, http.StatusBadRequest, "Missing label", "", nil)
		return
	}

	expiration := time.Now().Add(ssas.MacaroonExpiration)
	ct, m, err := system.SaveClientToken(r.Context(), body["label"], group.XData, expiration)
	if err != nil {
		errLog.Error(logrus.Fields{"Help": fmt.Sprintf("could not save client token for clientID %s, groupID %s: %s", system.ClientID, system.GroupID, err.Error())})
		service.JSONError(w, http.StatusInternalServerError, "Internal Error", "", nil)
	}

	response := ssas.ClientTokenResponse{
		ClientTokenOutput: ssas.OutputCT(*ct)[0],
		Token:             m,
	}

	b, err = json.Marshal(response)
	if err != nil {
		errLog.Error(logrus.Fields{"Help": fmt.Sprintf("could not marshal response for clientID %s, groupID %s: %s", system.ClientID, system.GroupID, err.Error())})
		service.JSONError(w, http.StatusInternalServerError, "Internal Error", "", nil)
	}

	_, err = w.Write(b)
	if err != nil {
		service.JSONError(w, http.StatusInternalServerError, "internal error", "", logger)
	}
}

func deleteToken(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	tokenID := chi.URLParam(r, "id")
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "DeleteToken", "TrackingID": trackingID, "Help": "calling from admin.deleteToken()"}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)
	errLog := logger.WithField("Event", "OperationFailed")
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		errLog.Error()
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", nil)
		return
	}

	logger.Info(logrus.Fields{"Event": "OperationCalled"})
	err = system.DeleteClientToken(r.Context(), tokenID)
	if err != nil {
		errLog.Error()
		service.JSONError(w, http.StatusInternalServerError, "Failed to delete client token", "", nil)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func createKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "CreateKey", "TrackingID": trackingID, "Help": "calling from admin.createKey()"}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)

	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed"})
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", nil)
		return
	}

	var pk ssas.PublicKeyInput
	if err := json.NewDecoder(r.Body).Decode(&pk); err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed"})
		service.JSONError(w, http.StatusBadRequest, "Failed to read body", "", nil)
		return
	}

	key, err := system.AddAdditionalPublicKey(strings.NewReader(pk.PublicKey), pk.Signature)
	if err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed"})
		service.JSONError(w, http.StatusInternalServerError, "Failed to add additional public key", "", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	keyStr := strings.Replace(key.Body, "\n", "\\n", -1)
	fmt.Fprintf(w, `{ "client_id": "%s", "public_key": "%s", "id": "%s"}`, system.ClientID, keyStr, key.UUID)
}

func deleteKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	keyID := chi.URLParam(r, "id")

	trackingID := ssas.RandomHexID()
	event := logrus.Fields{"Op": "DeleteKey", "TrackingID": trackingID, "Help": "calling from admin.deleteKey()"}
	logger := log.GetCtxLogger(r.Context()).WithFields(event)

	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed"})
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "", nil)
		return
	}

	if err := system.DeleteEncryptionKey(r.Context(), trackingID, keyID); err != nil {
		logger.Error(logrus.Fields{"Event": "OperationFailed"})
		service.JSONError(w, http.StatusInternalServerError, "Failed to delete key", "", nil)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

type IPAddressInput struct {
	Address string `json:"address"`
}

package admin

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/pborman/uuid"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

/*
	swagger:route POST /group group createGroup

	Create group

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
	groupEvent := ssas.Event{Op: "CreateGroup", TrackingID: trackingID}

	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)
	gd := ssas.GroupData{}
	err := json.Unmarshal(body, &gd)
	if err != nil {
		groupEvent.Help = fmt.Sprintf("error in request to create group; raw request: %v; error: %v", body, err.Error())
		ssas.OperationFailed(groupEvent)
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	groupEvent.Help = fmt.Sprintf("calling from admin.createGroup(), raw request: %v", string(body))
	ssas.OperationCalled(groupEvent)
	g, err := ssas.CreateGroup(gd, trackingID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("failed to create group; %s", err))
		return
	}

	groupJSON, err := json.Marshal(g)
	if err != nil {
		groupEvent.Help = err.Error()
		ssas.OperationFailed(groupEvent)
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(groupJSON)
	if err != nil {
		groupEvent.Help = err.Error()
		ssas.OperationFailed(groupEvent)
		jsonError(w, http.StatusInternalServerError, "internal error")
	}
}

/*
	swagger:route GET /group group listGroups

	List groups

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
	trackingID := uuid.NewRandom().String()

	ssas.OperationCalled(ssas.Event{Op: "ListGroups", TrackingID: trackingID, Help: "calling from admin.listGroups()"})
	groups, err := ssas.ListGroups(trackingID)
	if err != nil {
		ssas.OperationFailed(ssas.Event{Op: "admin.listGroups", TrackingID: trackingID, Help: err.Error()})
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}

	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		ssas.OperationFailed(ssas.Event{Op: "admin.listGroups", TrackingID: trackingID, Help: err.Error()})
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupsJSON)
	if err != nil {
		ssas.OperationFailed(ssas.Event{Op: "admin.listGroups", TrackingID: trackingID, Help: err.Error()})
		jsonError(w, http.StatusInternalServerError, "internal error")
	}
}

/*
	swagger:route PUT /group/{groupId} group updateGroup

	Update group

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
	groupEvent := ssas.Event{Op: "UpdateGroup", TrackingID: trackingID}

	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)
	gd := ssas.GroupData{}
	err := json.Unmarshal(body, &gd)
	if err != nil {
		groupEvent.Help = fmt.Sprintf("error in request to create group; raw request: %v; error: %v", body, err.Error())
		ssas.OperationFailed(groupEvent)
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	groupEvent.Help = fmt.Sprintf("calling from admin.updateGroup(), raw request: %v", string(body))
	ssas.OperationCalled(groupEvent)
	g, err := ssas.UpdateGroup(id, gd)
	if err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("failed to update group; %s", err))
		return
	}

	groupJSON, err := json.Marshal(g)
	if err != nil {
		groupEvent.Help = err.Error()
		ssas.OperationFailed(groupEvent)
		jsonError(w, http.StatusInternalServerError, "internal error")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupJSON)
	if err != nil {
		groupEvent.Help = err.Error()
		ssas.OperationFailed(groupEvent)
		jsonError(w, http.StatusInternalServerError, "internal error")
	}
}

/*
	swagger:route DELETE /group/{groupId} group deleteGroup

	Delete group

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

	ssas.OperationCalled(ssas.Event{Op: "DeleteGroup", TrackingID: id, Help: "calling from admin.deleteGroup()"})
	err := ssas.DeleteGroup(id)
	if err != nil {
		ssas.OperationFailed(ssas.Event{Op: "admin.deleteGroup", TrackingID: id, Help: err.Error()})
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("failed to delete group; %s", err))
		return
	}

	w.WriteHeader(http.StatusOK)
}

/*
	swagger:route POST /system system createSystem

	Create system

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
	if err := json.NewDecoder(r.Body).Decode(&sys); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ssas.OperationCalled(ssas.Event{Op: "RegisterClient", TrackingID: sys.TrackingID, Help: "calling from admin.createSystem()"})
	creds, err := ssas.RegisterSystem(sys.ClientName, sys.GroupID, sys.Scope, sys.PublicKey, sys.IPs, sys.TrackingID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("could not create system; %s", err))
		return
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
	}
}

/*
	swagger:route PUT /system/{systemId}/credentials system resetCredentials

	Reset credentials

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

	system, err := ssas.GetSystemByID(systemID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Invalid system ID")
		return
	}

	trackingID := uuid.NewRandom().String()
	ssas.OperationCalled(ssas.Event{Op: "ResetSecret", TrackingID: trackingID, Help: "calling from admin.resetCredentials()"})
	creds, err := system.ResetSecret(trackingID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
	}
}

/*
	swagger:route GET /system/{systemId}/key system getPublicKey

	Get Public Key

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

	system, err := ssas.GetSystemByID(systemID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "invalid system ID")
		return
	}

	trackingID := uuid.NewRandom().String()
	ssas.OperationCalled(ssas.Event{Op: "GetEncryptionKey", TrackingID: trackingID, Help: "calling from admin.getPublicKey()"})
	key, _ := system.GetEncryptionKey(trackingID)

	w.Header().Set("Content-Type", "application/json")
	keyStr := strings.Replace(key.Body, "\n", "\\n", -1)
	fmt.Fprintf(w, `{ "client_id": "%s", "public_key": "%s" }`, system.ClientID, keyStr)
}

/*
	swagger:route DELETE /system/{systemId}/credentials system deleteCredentials

	Delete credentials

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

	system, err := ssas.GetSystemByID(systemID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "invalid system ID")
		return
	}
	err = system.RevokeSecret(systemID)

	if err != nil {
		jsonError(w, http.StatusInternalServerError, "invalid system ID")
		return
	}

	w.WriteHeader(http.StatusOK)
}

/*
  	swagger:route DELETE /token/{tokenId} token revokeToken

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

	event := ssas.Event{Op: "TokenBlacklist", TokenID: tokenID}
	ssas.OperationCalled(event)

	if err := service.TokenBlacklist.BlacklistToken(tokenID, service.TokenCacheLifetime); err != nil {
		event.Help = err.Error()
		ssas.OperationFailed(event)
		jsonError(w, http.StatusInternalServerError, "internal server error")
	}

	w.WriteHeader(http.StatusOK)
}

func jsonError(w http.ResponseWriter, errorStatus int, description string) {
	service.JsonError(w, errorStatus, http.StatusText(errorStatus), description)
}

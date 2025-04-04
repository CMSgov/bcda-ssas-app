package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
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
	ssas.SetCtxEntry(r, "Op", "CreateGroup")
	logger := ssas.GetCtxLogger(r.Context())
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	gd := ssas.GroupData{}
	err := json.Unmarshal(body, &gd)
	if err != nil {
		logger.Errorf("error in request to create group; raw request: %v; error: %v", body, err.Error())
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	logger.Infof("calling from admin.createGroup(), raw request: %v", string(body))
	g, err := ssas.CreateGroup(r.Context(), gd)
	if err != nil {
		logger.Errorf("failed to create group; %s", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "failed to create group")
		return
	}

	groupJSON, err := json.Marshal(g)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(groupJSON)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
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
	ssas.SetCtxEntry(r, "Op", "ListGroups")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Info("calling from admin.listGroups()")
	groups, err := ssas.ListGroups(r.Context())
	if err != nil {
		logger.Error(err.Error())
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupsJSON)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
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
	ssas.SetCtxEntry(r, "Op", "ListGroup")
	logger := ssas.GetCtxLogger(r.Context())
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	gd := ssas.GroupData{}
	err := json.Unmarshal(body, &gd)
	if err != nil {
		logger.Error("failed to unmarshal JSON: ", err)
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	logger.Infof("calling from admin.updateGroup(), raw request: %v", string(body))
	g, err := ssas.UpdateGroup(r.Context(), id, gd)
	if err != nil {
		logger.Errorf("failed to update group; %s", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("failed to update group; %s", err))
		return
	}

	groupJSON, err := json.Marshal(g)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupJSON)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func getSystem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ssas.SetCtxEntry(r, "Op", "GetSystem")
	logger := ssas.GetCtxLogger(r.Context())

	s, err := ssas.GetSystemByID(r.Context(), id)
	if err != nil {
		logger.Errorf("could not find system %s", id)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), fmt.Sprintf("could not find system %s", id))
		return
	}

	ips, err := s.GetIPsData(r.Context())
	if err != nil {
		logger.Errorf("failed to find system", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "")
		return
	}
	cts, err := s.GetClientTokens(r.Context())
	if err != nil {
		logger.Errorf("failed to find token(s)", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "")
		return
	}
	eks, err := s.GetEncryptionKeys(r.Context())
	if err != nil {
		logger.Errorf("failed to find encryption keys", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "")
		return
	}

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
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(systemJSON)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func updateSystem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ssas.SetCtxEntry(r, "Op", "UpdateSystem")
	logger := ssas.GetCtxLogger(r.Context())
	defer r.Body.Close()

	var v map[string]string
	err := json.NewDecoder(r.Body).Decode(&v)
	if err != nil {
		logger.Error("invalid request body")
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

	logger.Info("Operation Called: admin.updateSystem()")

	//If attribute is in map, then update is allowed. if value is true, field can have an empty value.
	mutableFields := map[string]bool{"api_scope": false, "client_name": false, "software_id": true}
	for k, val := range v {
		blankAllowed, updateAllowed := mutableFields[k]
		if !updateAllowed {
			logger.Errorf("attribute: %v is not valid", k)
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("attribute: %v is not valid", k))
			return
		}
		if !blankAllowed && val == "" {
			logger.Errorf("attribute: %v is not valid", k)
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), fmt.Sprintf("attribute: %v may not be empty", k))
			return
		}
	}

	_, err = ssas.UpdateSystem(r.Context(), id, v)
	if err != nil {
		logger.Errorf("failed to update system; %s", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "failed to update system")
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
	ssas.SetCtxEntry(r, "Op", "DeleteGroup")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Info("Operation Called: admin.deleteGroup()")
	err := ssas.DeleteGroup(r.Context(), id)
	if err != nil {
		logger.Errorf("failed to delete group; %s", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "failed to delete group")
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
	ssas.SetCtxEntry(r, "Op", "CreateSystem")
	logger := ssas.GetCtxLogger(r.Context())
	if err := json.NewDecoder(r.Body).Decode(&sys); err != nil {
		logger.Error()
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	logger.Infof("Operation Called: admin.createSystem()")
	creds, err := ssas.RegisterSystem(r.Context(), sys.ClientName, sys.GroupID, sys.Scope, sys.PublicKey, sys.IPs, sys.TrackingID)
	if err != nil {
		logger.Errorf("failed to create system; %s", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "failed to create system")
		return
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func createV2System(w http.ResponseWriter, r *http.Request) {
	sys := ssas.SystemInput{}
	ssas.SetCtxEntry(r, "Op", "CreateV2System")
	logger := ssas.GetCtxLogger(r.Context())
	if err := json.NewDecoder(r.Body).Decode(&sys); err != nil {
		logger.Error()
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	logger.Infof("Operation Called: admin.createV2System()")
	creds, err := ssas.RegisterV2System(r.Context(), sys)
	if err != nil {
		logger.Errorf("failed to create v2 system; %s", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "could not create system")
		return
	}

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
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
	ssas.SetCtxEntry(r, "Op", "ResetSecret")
	logger := ssas.GetCtxLogger(r.Context())
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error()
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	logger.Infof("Operation Called: admin.resetCredentials()")
	creds, err := system.ResetSecret(r.Context())
	if err != nil {
		logger.Errorf("failed to reset secret: %s", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
	logger.Info("secret reset for system: ", system.ClientID)

	credsJSON, err := json.Marshal(creds)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
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
	ssas.SetCtxEntry(r, "Op", "GetPublicKey")

	logger := ssas.GetCtxLogger(r.Context())
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error("invalid system ID")
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "invalid system ID")
		return
	}

	logger.Infof("Operation Called: admin.getPublicKey()")
	key, _ := system.GetEncryptionKey(r.Context())

	w.Header().Set("Content-Type", "application/json")
	keyStr := strings.ReplaceAll(key.Body, "\n", "\\n")
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
	logger := ssas.GetCtxLogger(r.Context())
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error("invalid system ID")
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "invalid system ID")
		return
	}
	err = system.RevokeSecret(r.Context(), systemID)

	if err != nil {
		logger.Error("failed to revoke secret", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	logger.Info("secret revoked for client: ", system.ClientID)

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

	if tokenID == "" {
		service.JSONError(w, http.StatusBadRequest, "Missing tokenID", "")
		return
	}

	ssas.SetCtxEntry(r, "Op", "TokenBlacklist")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Infof("Operation Called: admin.revokeToken()")

	if err := service.TokenBlacklist.BlacklistToken(r.Context(), tokenID, service.TokenCacheLifetime); err != nil {
		logger.Errorf("failed to blacklist token; %s", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}

	logger.Info("token revoked for: ", tokenID)
	w.WriteHeader(http.StatusOK)
}

func registerIP(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ssas.SetCtxEntry(r, "Op", "RegisterIP")
	logger := ssas.GetCtxLogger(r.Context())
	input := IPAddressInput{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Error()
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid request body")
		return
	}

	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Errorf("failed to retrieve system; %s", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	if !ssas.ValidAddress(input.Address) {
		logger.Errorf("invalid ip address; %s", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid ip address")
		return
	}

	logger.Infof("Operation Called: admin.registerIP()")
	ip, err := system.RegisterIP(r.Context(), input.Address)
	if err != nil {
		// TODO there is another case where the IP address may be invalid
		if strings.Contains(err.Error(), "can not create duplicate IP address") {
			logger.Errorf("duplicate ip address; %s", err)
			service.JSONError(w, http.StatusConflict, http.StatusText(http.StatusConflict), "duplicate ip address")
			return
		}
		if strings.Contains(err.Error(), "max number of ips reached") {
			logger.Errorf("max ip addresses reached; %s", err)
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "max ip addresses reached")
			return
		}
		logger.Error(err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
	logger.Info("token created for client: ", system.ClientID)

	ipJson, err := json.Marshal(ip)
	if err != nil {
		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(ipJson)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func getSystemIPs(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ssas.SetCtxEntry(r, "Op", "GetSystemIPs")
	logger := ssas.GetCtxLogger(r.Context())
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error()
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	logger.Infof("Operation Called: admin.getSystemIPs()")
	ips, err := system.GetIps(r.Context())
	if err != nil {
		logger.Error("Could not retrieve system ips", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "")
		return
	}

	ipJson, err := json.Marshal(ips)
	if err != nil {
		logger.Error("unable to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(ipJson)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
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
	ssas.SetCtxEntry(r, "Op", "deleteSystemIPs")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Infof("Operation Called: admin.deleteSystemIP()")

	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error("failed to retrieve system", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	err = system.DeleteIP(r.Context(), ipID)
	if err != nil {
		logger.Errorf("failed to delete IP: %s", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "failed to delete IP")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func createToken(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ssas.SetCtxEntry(r, "Op", "CreateToken")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Infof("Operation Called: admin.createToken()")

	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error("failed to retrieve system", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	group, err := ssas.GetGroupByGroupID(r.Context(), system.GroupID)
	if err != nil {
		logger.Error("failed to retrieve group", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	var body map[string]string
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error(err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	if err := json.Unmarshal(b, &body); err != nil {
		logger.Error("unable to marshal JSON: ", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	if body["label"] == "" {
		logger.Error("missing label")
		service.JSONError(w, http.StatusBadRequest, "Missing label", "")
		return
	}

	expiration := time.Now().Add(ssas.MacaroonExpiration)
	ct, m, err := system.SaveClientToken(r.Context(), body["label"], group.XData, expiration)
	if err != nil {

		logger.Error("failed to save client token: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}

	response := ssas.ClientTokenResponse{
		ClientTokenOutput: ssas.OutputCT(*ct)[0],
		Token:             m,
	}

	b, err = json.Marshal(response)
	if err != nil {

		logger.Error("failed to marshal JSON: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}

	_, err = w.Write(b)
	if err != nil {
		logger.Error("failed to write response: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func deleteToken(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	tokenID := chi.URLParam(r, "id")
	ssas.SetCtxEntry(r, "Op", "GetSystemIPs")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Infof("Operation Called: admin.getSystemIPs()")
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error("failed to retrieve system", err)
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "")
		return
	}

	err = system.DeleteClientToken(r.Context(), tokenID)
	if err != nil {
		logger.Error("failed to delete client token", err)
		service.JSONError(w, http.StatusInternalServerError, "Failed to delete client token", "")
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func createKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ssas.SetCtxEntry(r, "Op", "CreateKey")
	logger := ssas.GetCtxLogger(r.Context())

	logger.Infof("Operation Called: admin.CreateKey()")
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error("failed to get system: ", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	var pk ssas.PublicKeyInput
	if err := json.NewDecoder(r.Body).Decode(&pk); err != nil {
		logger.Error("failed to decode: ", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "Failed to read body")
		return
	}

	if pk.PublicKey == "" || pk.Signature == "" {
		logger.Error("failed to receive PublicKey and/or Signature")
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	key, err := system.AddAdditionalPublicKey(strings.NewReader(pk.PublicKey), pk.Signature)
	if err != nil {
		logger.Error("failed to add additional public key: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	keyStr := strings.ReplaceAll(key.Body, "\n", "\\n")
	fmt.Fprintf(w, `{ "client_id": "%s", "public_key": "%s", "id": "%s"}`, system.ClientID, keyStr, key.UUID)
}

func deleteKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	keyID := chi.URLParam(r, "id")
	ssas.SetCtxEntry(r, "Op", "DeleteKey")
	logger := ssas.GetCtxLogger(r.Context())
	logger.Infof("Operation Called: admin.DeleteKey()")
	system, err := ssas.GetSystemByID(r.Context(), systemID)
	if err != nil {
		logger.Error("failed to get system: ", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	if err := system.DeleteEncryptionKey(r.Context(), keyID); err != nil {
		logger.Error("failed to delete key: ", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

type IPAddressInput struct {
	Address string `json:"address"`
}

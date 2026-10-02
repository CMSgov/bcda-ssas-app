package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"gorm.io/gorm"
)

type adminHandler struct {
	db *gorm.DB
	sr ssas.SystemRepository
	gr ssas.GroupRepository
	m  Marshaler
}

type Marshaler interface {
	Marshal(any) ([]byte, error)
	Unmarshal(data []byte, v any) error
}

type JsonMarshaler struct{}

func (j JsonMarshaler) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (j JsonMarshaler) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func NewAdminHandler(s ssas.SystemRepository, g ssas.GroupRepository, db *gorm.DB, m Marshaler) *adminHandler {
	return &adminHandler{
		sr: s,
		gr: g,
		db: db,
		m:  m,
	}
}

func (h *adminHandler) getInfo(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, adminInfo())
}

func (h *adminHandler) getVersion(w http.ResponseWriter, r *http.Request) {
	respMap := make(map[string]string)
	respMap["version"] = fmt.Sprintf("%v", constants.Version)
	render.JSON(w, r, respMap)
}

func (h *adminHandler) getHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, _ := ssas.SetCtxEntry(r, "Op", "getHealthCheck")
	m := make(map[string]string)
	if service.DoHealthCheck(ctx, h.db) {
		m["database"] = "ok"
		w.WriteHeader(http.StatusOK)
	} else {
		m["database"] = "error"
		w.WriteHeader(http.StatusBadGateway)
	}
	render.JSON(w, r, m)
}

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
func (h *adminHandler) createGroup(w http.ResponseWriter, r *http.Request) {
	ctx, logger := ssas.SetCtxEntry(r, "Op", "createGroup")
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("failed to read request body: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	gd := ssas.GroupData{}
	err = h.m.Unmarshal(body, &gd)
	if err != nil {
		logger.Errorf("failed to unmarshal request to create group: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	g, err := h.gr.CreateGroup(ctx, gd)
	if err != nil {
		logger.Errorf("failed to create group: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "failed to create group")
		return
	}

	groupJSON, err := h.m.Marshal(g)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(groupJSON) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
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
func (h *adminHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	ctx, logger := ssas.SetCtxEntry(r, "Op", "listGroups")
	logger.Info("Operation Called: admin.listGroups()")

	groups, err := h.gr.ListGroups(ctx)
	if err != nil {
		logger.Errorf("failed to list groups: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	groupsJSON, err := h.m.Marshal(groups)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupsJSON) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
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
func (h *adminHandler) updateGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "updateGroup")
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("failed to read request body: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}
	gd := ssas.GroupData{}

	err = h.m.Unmarshal(body, &gd)
	if err != nil {
		logger.Errorf("failed to unmarshal JSON: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	g, err := h.gr.UpdateGroup(ctx, id, gd)
	if err != nil {
		logger.Errorf("failed to update group, err: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "failed to update group")
		return
	}

	groupJSON, err := h.m.Marshal(g)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(groupJSON) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func (h *adminHandler) getSystem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "getSystem")

	s, err := h.sr.GetSystemByID(ctx, id)
	if err != nil {
		logger.Errorf("failed to get system by ID %s, err: %v", id, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "could not find system")
		return
	}

	ips, err := h.sr.GetIPsData(ctx, s)
	if err != nil {
		logger.Errorf("failed to find IPs for system ID %s, err: %v", id, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "")
		return
	}
	cts, err := h.sr.GetClientTokens(ctx, s)
	if err != nil {
		logger.Errorf("failed to find token(s): %v", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "")
		return
	}
	eks, err := h.sr.GetEncryptionKeys(ctx, s)
	if err != nil {
		logger.Errorf("failed to find encryption keys: %v", err)
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

	systemJSON, err := h.m.Marshal(o)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(systemJSON) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func (h *adminHandler) updateSystem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "updateSystem")
	logger.Info("Operation Called: admin.updateSystem()")
	defer r.Body.Close()

	var v map[string]string
	err := json.NewDecoder(r.Body).Decode(&v)
	if err != nil {
		logger.Errorf("invalid request body: %v", err)
		service.JSONError(w, http.StatusBadRequest, "invalid request body", "")
		return
	}

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

	_, err = h.sr.UpdateSystem(ctx, id, v)
	if err != nil {
		logger.Errorf("failed to update system: %v", err)
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
func (h *adminHandler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "deleteGroup")
	logger.Info("Operation Called: admin.deleteGroup()")

	err := h.gr.DeleteGroup(ctx, id)
	if err != nil {
		logger.Errorf("failed to delete group, err: %s", err)
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
func (h *adminHandler) createSystem(w http.ResponseWriter, r *http.Request) {
	sys := ssas.SystemInput{}
	ctx, logger := ssas.SetCtxEntry(r, "Op", "createSystem")
	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(&sys); err != nil {
		logger.Errorf("failed to decode body: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	creds, err := h.sr.RegisterSystem(ctx, sys.ClientName, sys.GroupID, sys.Scope, sys.PublicKey, sys.IPs, sys.TrackingID)
	if err != nil {
		logger.Errorf("failed to create system: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "failed to create system")
		return
	}

	group, err := h.gr.GetGroupByGroupID(ctx, sys.GroupID)
	if err != nil {
		logger.Errorf("failed to get group for clientID %s: %v", creds.ClientID, err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	// Used for alerting; update alert if this line changes
	logger.Infof("system registered in group %s with XData: %s", group.GroupID, group.XData)

	credsJSON, err := h.m.Marshal(creds)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func (h *adminHandler) createV2System(w http.ResponseWriter, r *http.Request) {
	sys := ssas.SystemInput{}
	ctx, logger := ssas.SetCtxEntry(r, "Op", "createV2System")
	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(&sys); err != nil {
		logger.Errorf("failed to decode body, err: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	creds, err := h.sr.RegisterV2System(ctx, sys)
	if err != nil {
		logger.Errorf("failed to create v2 system: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "could not create system")
		return
	}

	credsJSON, err := h.m.Marshal(creds)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(credsJSON) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
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
func (h *adminHandler) resetCredentials(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "resetCredentials")

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to get system by ID %s, err: %v", systemID, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	xdata, err := h.gr.XDataFor(ctx, system)
	if err != nil {
		logger.Errorf("could not get group XData for clientID %s, err: %v", system.ClientID, err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	creds, err := h.sr.ResetSecret(ctx, system)
	if err != nil {
		logger.Errorf("failed to reset secret: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	logger.Infof("secret reset in group %s with XData: %s", system.GroupID, xdata)

	credsJSON, err := h.m.Marshal(creds)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	_, err = w.Write(credsJSON) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
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
func (h *adminHandler) getPublicKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "getPublicKey")

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("invalid system ID: %v", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "invalid system ID")
		return
	}

	key, _ := h.sr.GetEncryptionKey(ctx, system)
	w.Header().Set("Content-Type", "application/json")
	keyStr := strings.ReplaceAll(key.Body, "\n", "\\n")
	fmt.Fprintf(w, `{ "client_id": "%s", "public_key": "%s" }`, system.ClientID, keyStr) // #nosec G705
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
func (h *adminHandler) deactivateSystemCredentials(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "deactivateSystemCredentials")

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to get system by ID %s, err: %v", systemID, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "invalid system ID")
		return
	}

	xdata, err := h.gr.XDataFor(ctx, system)
	if err != nil {
		logger.Errorf("failed to get group XData for clientID %s, err: %v", system.ClientID, err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	err = h.sr.RevokeSecret(ctx, system)
	if err != nil {
		logger.Errorf("failed to revoke secret: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	// Used for alerting; update alert if this line changes
	logger.Infof("secret revoked in group %s with XData: %s", system.GroupID, xdata)

	w.WriteHeader(http.StatusOK)
}

/*
	  	swagger:route DELETE /token/{token_id} token revokeToken

		Revoke token

		Revokes the specified tokenID by placing it on a denylist.  Will return an HTTP 200 status whether or not the tokenID has been issued.

		Produces:
		- application/json

		Security:
			basic_auth:

		Responses:
			200: okResponse
			401: invalidCredentials
			500: serverError
*/
func (h *adminHandler) revokeToken(w http.ResponseWriter, r *http.Request) {
	ctx, logger := ssas.SetCtxEntry(r, "Op", "revokeToken")

	tokenID := chi.URLParam(r, "tokenID")
	if tokenID == "" {
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "missing token ID")
		return
	}

	if err := service.TokenDenylist.DenylistToken(ctx, tokenID, service.TokenCacheLifetime); err != nil {
		logger.Errorf("failed to denylist token: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}

	logger.Infof("token revoked for: %s", tokenID)
	w.WriteHeader(http.StatusOK)
}

func (h *adminHandler) registerIP(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "registerIP")
	defer r.Body.Close()

	input := IPAddressInput{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Errorf("failed to decode request body: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid request body")
		return
	}

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to retrieve system: %v", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	if !ssas.ValidAddress(input.Address) {
		logger.Errorf("invalid ip address: %s", input.Address)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "invalid ip address")
		return
	}

	ip, err := h.sr.RegisterIP(ctx, system, input.Address)
	if err != nil {
		// TODO there is another case where the IP address may be invalid
		if strings.Contains(err.Error(), "can not create duplicate IP address") {
			logger.Errorf("duplicate ip address: %v", err)
			service.JSONError(w, http.StatusConflict, http.StatusText(http.StatusConflict), "duplicate ip address")
			return
		}
		if strings.Contains(err.Error(), "max number of ips reached") {
			logger.Errorf("max ip addresses reached: %v", err)
			service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "max ip addresses reached")
			return
		}
		logger.Errorf("other error registering IP address, err: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	logger.Infof("IP registered for client: %s", system.ClientID)

	ipJson, err := h.m.Marshal(ip)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(ipJson) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
	}
}

func (h *adminHandler) getSystemIPs(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "getSystemIPs")

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to get system by ID %s, err: %v", systemID, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	ips, err := h.sr.GetIps(ctx, system)
	if err != nil {
		logger.Errorf("Could not retrieve system ips: %v", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "")
		return
	}

	ipJson, err := h.m.Marshal(ips)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(ipJson) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
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
func (h *adminHandler) deleteSystemIP(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ipID := chi.URLParam(r, "id")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "deleteSystemIP")

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to get system by ID %s, err: %v", systemID, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	err = h.sr.DeleteIP(ctx, system, ipID)
	if err != nil {
		logger.Errorf("failed to delete IP: %v", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "failed to delete IP")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *adminHandler) createToken(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "createToken")
	defer r.Body.Close()

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to retrieve system: %v", err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	group, err := h.gr.GetGroupByGroupID(ctx, system.GroupID)
	if err != nil {
		logger.Errorf("failed to get group: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	var body map[string]string
	b, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Errorf("failed to read body: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	if err := h.m.Unmarshal(b, &body); err != nil {
		logger.Errorf("failed to unmarshal JSON: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	if body["label"] == "" {
		logger.Error("missing label")
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "missing label")
		return
	}

	expiration := time.Now().Add(cfg.MacaroonExpiration)
	ct, m, err := h.sr.SaveClientToken(ctx, system, body["label"], group.XData, expiration)
	if err != nil {
		logger.Errorf("failed to save client token: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	response := ssas.ClientTokenResponse{
		ClientTokenOutput: ssas.OutputCT(*ct)[0],
		Token:             m,
	}

	b, err = h.m.Marshal(response)
	if err != nil {
		logger.Errorf("failed to marshal JSON: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	_, err = w.Write(b) // #nosec G705
	if err != nil {
		logger.Errorf("failed to write response: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}
}

func (h *adminHandler) deleteToken(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	tokenID := chi.URLParam(r, "id")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "deleteToken")

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to get system by ID: %s, err: %v", systemID, err)
		service.JSONError(w, http.StatusNotFound, "Invalid system ID", "")
		return
	}

	err = h.sr.DeleteClientToken(ctx, system, tokenID)
	if err != nil {
		logger.Errorf("failed to delete client token: %v", err)
		service.JSONError(w, http.StatusInternalServerError, "Failed to delete client token", "")
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (h *adminHandler) createKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "createKey")
	defer r.Body.Close()

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to get system by ID: %s, err: %v", systemID, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	var pk ssas.PublicKeyInput
	if err := json.NewDecoder(r.Body).Decode(&pk); err != nil {
		logger.Errorf("failed to decode JSON body: %v", err)
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "Failed to read body")
		return
	}

	if pk.PublicKey == "" || pk.Signature == "" {
		logger.Error("failed to receive PublicKey and/or Signature")
		service.JSONError(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest), "")
		return
	}

	key, err := h.sr.SavePublicKey(h.db, system, strings.NewReader(pk.PublicKey), pk.Signature, false)
	if err != nil {
		logger.Errorf("failed to add additional public key: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	keyStr := strings.ReplaceAll(key.Body, "\n", "\\n")
	fmt.Fprintf(w, `{ "client_id": "%s", "public_key": "%s", "id": "%s"}`, system.ClientID, keyStr, key.UUID) // #nosec G705
}

func (h *adminHandler) deleteKey(w http.ResponseWriter, r *http.Request) {
	systemID := chi.URLParam(r, "systemID")
	keyID := chi.URLParam(r, "id")
	ctx, logger := ssas.SetCtxEntry(r, "Op", "deleteKey")

	system, err := h.sr.GetSystemByID(ctx, systemID)
	if err != nil {
		logger.Errorf("failed to get system by ID: %s, err: %v", systemID, err)
		service.JSONError(w, http.StatusNotFound, http.StatusText(http.StatusNotFound), "Invalid system ID")
		return
	}

	if err := h.sr.DeleteEncryptionKey(ctx, system, keyID); err != nil {
		logger.Errorf("failed to delete key: %v", err)
		service.JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), "")
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

type IPAddressInput struct {
	Address string `json:"address"`
}

func adminInfo() map[string][]string {
	infoMap := make(map[string][]string)
	infoMap["banner"] = []string{fmt.Sprintf("%s server running on port %s", "public", ":3003")}

	routes, err := server.ListRoutes()
	if err != nil {
		infoMap["routes"] = []string{"error listing routes"}
	} else {
		infoMap["routes"] = routes
	}

	return infoMap
}

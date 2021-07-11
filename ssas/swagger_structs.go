package ssas

import (
	"fmt"
	"time"
)

// The requested operation was successful.  There is no body returned.
// swagger:response okResponse
type OkResponse struct{}

// The request is invalid or malformed
// swagger:response badRequestResponse
type BadRequestResponse struct {
	// Invalid request
	// in: body
	Body ErrorResponse
}

// Required credentials are missing or invalid
// swagger:response invalidCredentials
type InvalidCredentialsResponse struct {
	// Invalid credentials
	// in: body
	Body ErrorResponse
}

// An internal server error has occurred
// swagger:response serverError
type ServerErrorResponse struct {
	// Internal server error
	// in: body
	Body ErrorResponse
}

// The specified resource is not found
// swagger:response notFoundResponse
type NotFoundResponse struct {
	// Resource not found
	// in: body
	Body ErrorResponse
}

type ErrorResponse struct {
	// Error type
	// Required: true
	Error string `json:"error"`
	// More information about the error
	ErrorDescription string `json:"error_description"`
}

// The successfully created/altered system is returned
// swagger:response systemResponse
type SystemResponse struct {
	// System details
	// in: body
	Body struct {
		// The client ID for this system
		// Required: true
		ClientID string `json:"client_id"`
		// The client secret for this system
		// Required: true
		ClientSecret string `json:"client_secret"`
		// This system's ID
		// Required: true
		SystemID string `json:"system_id"`
		// The user-specified name for the system
		// Required: true
		ClientName string `json:"client_name"`
		// The expiration date for these credentials
		// Required: true
		ExpiresAt time.Time `json:"expires_at"`
		// Optional IP addresses from which this system is allowed to connect
		// Required: false
		IPs []string `json:"ips,omitempty"`
	}
}

// The group was successfully created/altered
// swagger:response groupResponse
type GroupResponse struct {
	// Group details
	// in: body
	Body struct {
		// The group's ID
		// Required: true
		ID int `json:"id"`
		// Creation timestamp for the group
		// Required: false
		CreatedAt time.Time `json:"created_at"`
		// Last update timestamp for the group
		// Required: false
		UpdatedAt time.Time `json:"updated_at"`
		// The date at which the group was deleted.  This is unlikely to be present in API output.
		// Required: false
		DeletedAt time.Time `json:"deleted_at"`
		// The user-provided identifier for the group
		// Required: true
		GroupID string `json:"group_id"`
		// The user-provided data for the group, which should be associated with all systems in this group.
		// Required: true
		XData string `json:"xdata"`
		// A parsed version of the user-provided data
		// Required: true
		Data GroupSummary `json:"data"`
	}
}

// The specified system has a public key, which is returned
// swagger:response publicKeyResponse
type PublicKeyResponse struct {
	// Public key details
	// in: body
	Body struct {
		// This system's client ID
		// Required: true
		ClientID string `json:"client_id"`
		// The public key (if any) registered for this system
		// Required: true
		PublicKey string `json:"public_key"`
	}
}

// List of all registered groups
// swagger:response groupsResponse
type GroupsResponse struct {
	// List of groups
	// in: body
	Body struct {
		// The number of registered groups
		// Required: true
		Count int `json:"count"`
		// The time the request is received
		// Required: true
		ReportedAt time.Time `json:"reported_at"`
		// The list of groups currently registered
		// Required: true
		Groups []GroupSummary `json:"groups"`
	}
}

// swagger:parameters revokeToken
type TokenIDParam struct {
	// A token's ID
	// in: path
	// required: true
	TokenID string `json:"token_id"`
}

// swagger:parameters getPublicKey resetCredentials deleteCredentials deleteSystemIP
type SystemIDParam struct {
	// ID of system
	// in: path
	// required: true
	SystemID string `json:"system_id"`
}

// swagger:parameters updateGroup deleteGroup
type GroupIDParam struct {
	// ID of group
	// in: path
	// required: true
	GroupID string `json:"group_id"`
}

// swagger:parameters createGroup updateGroup
type GroupDataParam struct {
	// Data necessary to create or update a group
	// in: body
	// required: true
	Body GroupInput `json:"group_input"`
}

// swagger:parameters deleteSystemIP
type IpID struct {
	// ID of IP address
	// in: path
	// required: true
	IpID string `json:"ip_id"`
}

type GroupInput struct {
	// A user-specified unique identifier for the group
	// Example: 550ffb24-dd8a-439c-b700-dd664a66d5a7
	// Required: true
	GroupID string `json:"group_id"`
	// A human-readable name for the group
	// Example: My Test Group
	// Required: true
	Name string `json:"name"`
	// A packet of string data in JSON format that should be associated with this group's systems
	// Example: `{"cms_ids":["A9994"]}`
	// Required: true
	XData string `json:"xdata"`
	// Optional Okta user ID's that should be able to manage this group
	// Example: ["abcd123","wxyz456"]
	Users []string `json:"users,omitempty"`
	// Resources (e.g. which API's should be allowed) for systems in this group
	// Required: true
	Resources []Resource `json:"resources,omitempty"`
}

// swagger:parameters createSystem
type SystemDataParam struct {
	// Data necessary to create a system
	// in: body
	// required: true
	Body SystemInput `json:"system_input"`
}

type SystemInput struct {
	// A user-specified name for the system
	// Example: My Test System
	// Required: true
	ClientName string `json:"client_name"`
	// The group ID (user-specified unique string value) that the system should be attached to
	// Example: My Test Group
	// Required: true
	GroupID string `json:"group_id"`
	// The scope for this system
	// Example: bcda-api
	// Required: true
	Scope string `json:"scope"`
	// An optional RSA 2048-bit public key to register with this system
	PublicKey string `json:"public_key"`
	// An optional signature to verify the public key
	Signature string `json:"signature,omitempty"`
	// An optional list of public IP addresses (IPv4 or IPv6) from which this system can make requests
	IPs []string `json:"ips"`
	// A unique identifier for this request to assist in log correlation
	// Required: true
	TrackingID string `json:"tracking_id"`

	XData string `json:"xdata,omitempty"`
}

type ClientTokenOutput struct {
	ID           string    `json:"id"`
	CreationDate time.Time `json:"creation_date"`
	Label        string    `json:"label"`
	UUID         string    `json:"uuid"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func OutputCT(cts ...ClientToken) []ClientTokenOutput {
	var o = make([]ClientTokenOutput, 0)
	for _, v := range cts {
		t := ClientTokenOutput{
			ID:           fmt.Sprintf("%d", v.ID),
			CreationDate: v.CreatedAt,
			Label:        v.Label,
			UUID:         v.Uuid,
			ExpiresAt:    v.ExpiresAt,
		}
		o = append(o, t)
	}
	return o
}

type PublicKeyOutput struct {
	ID           string    `json:"id"`
	CreationDate time.Time `json:"creation_date"`
	Key          string    `json:"key"`
}

func OutputPK(eks ...EncryptionKey) []PublicKeyOutput {
	var o = make([]PublicKeyOutput, 0)
	for _, v := range eks {
		if v.Body == "" {
			continue
		}
		pk := &PublicKeyOutput{
			ID:           v.UUID,
			CreationDate: v.CreatedAt,
			Key:          v.Body,
		}
		o = append(o, *pk)
	}
	return o
}

type IPOutput struct {
	ID           string    `json:"id"`
	CreationDate time.Time `json:"creation_date"`
	IP           string    `json:"ip"`
}

func OutputIP(ips ...IP) []IPOutput {
	var o = make([]IPOutput, 0)
	for _, v := range ips {
		ip := IPOutput{
			ID:           fmt.Sprintf("%d", v.ID),
			CreationDate: v.CreatedAt,
			IP:           v.Address,
		}
		o = append(o, ip)
	}
	return o
}

type SystemOutput struct {
	GID          string              `json:"g_id"`
	GroupID      string              `json:"group_id"`
	ClientID     string              `json:"client_id"`
	SoftwareID   string              `json:"software_id"`
	ClientName   string              `json:"client_name"`
	APIScope     string              `json:"api_scope"`
	XData        string              `json:"x_data"`
	LastTokenAt  string              `json:"last_token_at"`
	PublicKeys   []PublicKeyOutput   `json:"public_keys"`
	IPs          []IPOutput          `json:"ips"`
	ClientTokens []ClientTokenOutput `json:"client_tokens"`
}

type PublicKeyInput struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

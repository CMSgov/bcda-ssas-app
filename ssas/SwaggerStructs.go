package ssas

import (
	"time"
)

// The requested operation was successful.  There is no body returned.
// swagger:response okResponse
type OkResponse struct {}

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
	Error				string
	// More information about the error
	ErrorDescription	string
}

// The successfully created/altered system is returned
// swagger:response systemResponse
type SystemResponse struct {
	// System details
	// in: body
	Body struct {
		// The client ID for this system
		// Required: true
		ClientID		string
		// The client secret for this system
		// Required: true
		ClientSecret	string
		// This system's ID
		// Required: true
		SystemID		string
		// The user-specified name for the system
		// Required: true
		ClientName		string
		// The expiration date for these credentials
		// Required: true
		ExpiresAt		time.Time
		// Optional IP addresses from which this system is allowed to connect
		// Required: false
		IPs				[]string	`json:"ips,omitempty"`
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
		ID        int
		// Creation timestamp for the group
		// Required: false
		CreatedAt time.Time
		// Last update timestamp for the group
		// Required: false
		UpdatedAt time.Time
		// The date at which the group was deleted.  This is unlikely to be present in API output.
		// Required: false
		DeletedAt time.Time
		// The user-provided identifier for the group
		// Required: true
		GroupID   string
		// The user-provided data for the group, which should be associated with all systems in this group.
		// Required: true
		XData     string `json:"xdata"`
		// A parsed version of the user-provided data
		// Required: true
		Data      GroupSummary
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
		ClientID	string	`json:"client_id"`
		// The public key (if any) registered for this system
		// Required: true
		PublicKey	string	`json:"public_key"`
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
		Count      int            `json:"count"`
		// The time the request is received
		// Required: true
		ReportedAt time.Time      `json:"reported_at"`
		// The list of groups currently registered
		// Required: true
		Groups     []GroupSummary `json:"groups"`
	}
}

// swagger:parameters revokeToken
type TokenIDParam struct {
	// A token's ID
	// in: path
	// required: true
	TokenID string `json:"tokenId"`
}

// swagger:parameters getPublicKey resetCredentials deleteCredentials
type SystemIDParam struct {
	// ID of system
	// in: path
	// required: true
	SystemID string `json:"systemId"`
}

// swagger:parameters updateGroup deleteGroup
type GroupIDParam struct {
	// ID of group
	// in: path
	// required: true
	GroupID string `json:"groupId"`
}

// swagger:parameters createGroup updateGroup
type GroupDataParam struct {
	// Data necessary to create or update a group
	// in: body
	// required: true
	Body GroupInput
}

type GroupInput struct {
	// A user-specified unique identifier for the group
	// Example: 550ffb24-dd8a-439c-b700-dd664a66d5a7
	// Required: true
	GroupID   string     `json:"group_id"`
	// A human-readable name for the group
	// Example: My Test Group
	// Required: true
	Name      string     `json:"name"`
	// A packet of string data in JSON format that should be associated with this group's systems
	// Example: `{"cms_ids":["A9994"]}`
	// Required: true
	XData     string     `json:"xdata"`
	// Optional Okta user ID's that should be able to manage this group
	// Example: ["abcd123","wxyz456"]
	Users     []string   `json:"users,omitempty"`
	// Resources (e.g. which API's should be allowed) for systems in this group
	// Required: true
	Resources []Resource `json:"resources,omitempty"`
}

// swagger:parameters createSystem
type SystemDataParam struct {
	// Data necessary to create a system
	// in: body
	// required: true
	Body SystemInput
}

type SystemInput struct {
	// A user-specified name for the system
	// Example: My Test System
	// Required: true
	ClientName string `json:"client_name"`
	// The group ID (user-specified unique string value) that the system should be attached to
	// Example: My Test Group
	// Required: true
	GroupID    string `json:"group_id"`
	// The scope for this system
	// Example: bcda-api
	// Required: true
	Scope      string `json:"scope"`
	// An optional RSA 2048-bit public key to register with this system
	PublicKey  string `json:"public_key"`
	// An optional list of public IP addresses (IPv4 or IPv6) from which this system can make requests
	IPs      []string `json:"ips"`
	// A unique identifier for this request to assist in log correlation
	// Required: true
	TrackingID string `json:"tracking_id"`
}
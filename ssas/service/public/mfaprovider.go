package public

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/okta"
)

const (
	Mock = "mock"
	Live = "live"
)

var providerName = Mock

func init() {
	SetProvider(strings.ToLower(os.Getenv(`SSAS_MFA_PROVIDER`)))
}

func SetProvider(name string) {
	n := strings.ToLower(name)
	if name != "" {
		switch n {
		case Live:
			providerName = n
		case Mock:
			providerName = n
		default:
			providerEvent := ssas.Event{Op: "SetProvider", Help: fmt.Sprintf(`Unknown providerName %s; using %s`, n, providerName)}
			ssas.ServiceStarted(providerEvent)
		}
	}
	providerEvent := ssas.Event{Op: "SetProvider", Help: fmt.Sprintf(`MFA is made possible by %s`, providerName)}
	ssas.ServiceStarted(providerEvent)
}

func GetProviderName() string {
	return providerName
}

func GetProvider() MFAProvider {
	switch providerName {
	case Live:
		return NewOktaMFA(okta.Client())
	case Mock:
		fallthrough
	default:
		return &MockMFAPlugin{}
	}
}

// PasswordReturn defines the return type of VerifyPassword
type PasswordReturn struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

// FactorReturn defines the return type of RequestFactorChallenge
type FactorReturn struct {
	Action      string       `json:"action"`
	Transaction *Transaction `json:"transaction,omitempty"`
}

// Transaction defines the extra information provided in a response to RequestFactorChallenge for Push factors
type Transaction struct {
	TransactionID string    `json:"transaction_id"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func ValidFactorType(factorType string) bool {
	switch strings.ToLower(factorType) {
	case "google totp":
		fallthrough
	case "okta totp":
		fallthrough
	case "push":
		fallthrough
	case "sms":
		fallthrough
	case "call":
		fallthrough
	case "email":
		return true
	default:
		return false
	}
}

// Provider defines operations performed through an Okta MFA provider.  This indirection allows for a mock provider
// to use during CI/CD integration testing
type MFAProvider interface {

	// VerifyPassword checks username/password validity, and returns information about the status of the account. Most
	// importantly for the MFA workflow, it indicates whether a successfully verified account is cleared to continue
	// MFA authentication, or whether a condition exists such as an expired password or no actively enrolled
	// MFA factors.
	VerifyPassword(userIdentifier string, password string, trackingId string) (*PasswordReturn, string, error)

	// RequestFactorChallenge sends an MFA challenge request for the MFA factor type registered to the specified user,
	// if both user and factor exist.  For instance, for the SMS factor type, an SMS message would be sent with a
	// passcode.  Responses for successful and failed attempts should not vary.
	RequestFactorChallenge(userIdentifier string, factorType string, trackingId string) (*FactorReturn, error)

	// VerifyFactorChallenge tests an MFA passcode for validity.  This function should be used for all factor types
	// except Push.
	VerifyFactorChallenge(userIdentifier string, factorType string, passcode string, trackingId string) (bool, string, []string)

	// VerifyFactorTransaction reports the status of a Push factor's transaction.  Possible non-error states include success,
	// rejection, waiting, and timeout.
	VerifyFactorTransaction(userIdentifier string, factorType string, transactionId string, trackingId string) (string, error)
}

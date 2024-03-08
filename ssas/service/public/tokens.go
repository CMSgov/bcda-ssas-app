package public

import (
	"fmt"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

var accessTokenCreator TokenCreator

var selfRegistrationTokenDuration time.Duration

func init() {
	minutes := cfg.GetEnvInt("SSAS_MFA_TOKEN_TIMEOUT_MINUTES", 60)
	selfRegistrationTokenDuration = time.Duration(int64(time.Minute) * int64(minutes))

	accessTokenCreator = AccessTokenCreator{}
}

func GetAccessTokenCreator() TokenCreator {
	return accessTokenCreator
}

// TokenCreator provides methods for the creation of tokens.
// Currently only AccessTokenCreator implements this interface.
// TO DO:
// Define a MFATokenCreator & a RegistrationTokenCreator that will implement TokenCreator interface,
// then add CreateCommonClaims to this interface that all 3 can share.
type TokenCreator interface {
	GenerateToken(claims service.CommonClaims) (*jwt.Token, string, error)
}

// AccessTokenCreator is an implementation of TokenCreator that creates access tokens.
type AccessTokenCreator struct {
}

// validates that AccessTokenCreator implements the TokenCreator interface
var _ TokenCreator = AccessTokenCreator{}

// MintRegistrationToken generates a tokenstring for system self-registration endpoints
func MintRegistrationToken(oktaID string, groupIDs []string) (*jwt.Token, string, error) {
	claims := service.CommonClaims{
		TokenType: "RegistrationToken",
		OktaID:    oktaID,
		GroupIDs:  groupIDs,
	}

	if err := checkTokenClaims(&claims); err != nil {
		return nil, "", err
	}

	return server.MintTokenWithDuration(&claims, selfRegistrationTokenDuration)
}

// GenerateToken generates a tokenstring that expires in server.tokenTTL time
func (accessTokenCreator AccessTokenCreator) GenerateToken(claims service.CommonClaims) (*jwt.Token, string, error) {
	if err := checkTokenClaims(&claims); err != nil {
		return nil, "", err
	}

	return server.MintToken(&claims)
}

func CreateCommonClaims(tokenType, oktaID, systemID, clientID, data, systemXData string, groupIDs []string) (claims service.CommonClaims) {
	claims = service.CommonClaims{
		TokenType:   tokenType,
		OktaID:      oktaID,
		GroupIDs:    groupIDs,
		SystemID:    systemID,
		ClientID:    clientID,
		Data:        data,
		SystemXData: systemXData,
	}
	return claims
}

func empty(arr []string) bool {
	empty := true
	for _, item := range arr {
		if item != "" {
			empty = false
			break
		}
	}
	return empty
}

func tokenValidity(tokenString string, requiredTokenType string) error {
	event := logrus.Fields{"Op": "tokenValidity"}
	logger := ssas.Logger.WithFields(event)
	logger.Info(ssas.OperationStarted)
	t, err := server.VerifyToken(tokenString)
	if err != nil {
		helpMsg := err.Error()
		logger.Error(ssas.OperationFailed, logrus.WithField("Help", helpMsg))
		return err
	}

	c := t.Claims.(*service.CommonClaims)

	err = checkAllClaims(c, requiredTokenType)
	if err != nil {
		helpMsg := err.Error()
		logger.Error(ssas.OperationFailed, logrus.WithField("Help", helpMsg))
		return err
	}

	err = c.Valid()
	if err != nil {
		helpMsg := err.Error()
		logger.Error(ssas.OperationFailed, logrus.WithField("Help", helpMsg))
		return err
	}

	if service.TokenBlacklist.IsTokenBlacklisted(c.Id) {
		err = fmt.Errorf("token has been revoked")
		helpMsg := err.Error()
		logger.Error(ssas.OperationFailed, logrus.WithField("Help", helpMsg))
		return err
	}

	logger.Info(ssas.OperationSucceeded)
	return nil
}

func checkAllClaims(claims *service.CommonClaims, requiredTokenType string) error {
	if err := server.CheckRequiredClaims(claims, requiredTokenType); err != nil {
		return err
	}

	if err := checkTokenClaims(claims); err != nil {
		return err
	}
	return nil
}

func checkTokenClaims(claims *service.CommonClaims) error {
	switch claims.TokenType {
	case "MFAToken":
		if claims.OktaID == "" {
			return fmt.Errorf("MFA token must have OktaID claim")
		}
	case "RegistrationToken":
		if empty(claims.GroupIDs) {
			return fmt.Errorf("registration token must have GroupIDs claim")
		}
	case "AccessToken":
		if claims.Data == "" {
			return fmt.Errorf("access token must have Data claim")
		}
	default:
		return fmt.Errorf("missing token type claim")
	}
	return nil
}

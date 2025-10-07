package public

import (
	"context"
	"fmt"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/service"
	"github.com/golang-jwt/jwt/v5"
)

type TokenCreator interface {
	GenerateToken(claims service.CommonClaims) (*jwt.Token, string, error)
}

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

	return server.MintTokenWithDuration(&claims, cfg.SelfRegistrationTokenDuration)
}

// AccessTokenCreator is an implementation of TokenCreator that creates access tokens.
type AccessTokenCreator struct {
}

// GenerateToken generates a tokenstring that expires in server.tokenTTL time
func (a AccessTokenCreator) GenerateToken(claims service.CommonClaims) (*jwt.Token, string, error) {
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

func tokenValidity(ctx context.Context, tokenString string, requiredTokenType string) error {
	logger := ssas.GetCtxLogger(ctx)

	t, err := server.VerifyToken(tokenString)
	if err != nil {
		logger.Error(err)
		return err
	}
	if !t.Valid {
		err = fmt.Errorf("token is not valid")
		logger.Error(err)
		return err
	}

	c := t.Claims.(*service.CommonClaims)

	err = checkAllClaims(c, requiredTokenType)
	if err != nil {
		logger.Error(err)
		return err
	}

	if service.TokenDenylist.IsTokenDenylisted(c.ID) {
		err = fmt.Errorf("token has been revoked")
		logger.Error(err)
		return err
	}
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

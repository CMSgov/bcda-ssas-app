package service

import (
	"errors"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/golang-jwt/jwt/v4"
)

type TokenFlaw int

const (
	Postdated TokenFlaw = iota
	Expired
	ExtremelyExpired
	BadSigner // Since the signing key is a parameter to BadToken(), this flaw must be introduced elsewhere
	BadIssuer
	MissingID
)

// BadToken creates invalid tokens for testing.  To avoid exposing token spoofing capabilities, a limited number of
// bad token types will be supported.
func BadToken(claims *CommonClaims, flaw TokenFlaw, keyPath string) (token *jwt.Token, signedString string, err error) {
	signingKey, err := GetPrivateKey(keyPath)
	if err != nil {
		return
	}
	signingMethod := jwt.SigningMethodRS512
	tokenID := newTokenID()
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(20 * time.Minute).Unix()
	claims.Id = tokenID
	claims.Issuer = "ssas"

	switch flaw {
	case Postdated:
		claims.IssuedAt = time.Now().Add(time.Hour).Unix()
		claims.ExpiresAt = time.Now().Add(time.Hour).Add(time.Minute).Unix()
	case Expired:
		claims.IssuedAt = time.Now().Add(-2 * time.Minute).Unix()
		claims.ExpiresAt = time.Now().Add(-1 * time.Minute).Unix()
	case ExtremelyExpired:
		claims.IssuedAt = time.Now().Add(-30 * 24 * time.Hour).Unix()
		claims.ExpiresAt = time.Now().Add(-30 * 24 * time.Hour).Add(time.Minute).Unix()
	case BadSigner:
		// No-op; the signer is managed by the caller
	case BadIssuer:
		claims.Issuer = "bad_actor"
	case MissingID:
		claims.Id = ""
	default:
		signedString = "this_is_a_bad_signed_string"
		err = errors.New("unknown token flaw")
		return
	}

	token = jwt.New(signingMethod)
	token.Claims = claims
	signedString, err = token.SignedString(signingKey)
	if err != nil {
		ssas.Logger.Error("token signing error " + err.Error())
	}
	return
}

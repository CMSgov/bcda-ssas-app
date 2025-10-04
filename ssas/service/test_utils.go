package service

import (
	"errors"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/golang-jwt/jwt/v5"
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

const TestAdminClientID = "31e029ef-0e97-47f8-873c-0e8b7e7f99bf" // gitleaks:allow
const TestGroupID = "0c527d2e-2e8a-4808-b11d-0fa06baf8254"       // gitleaks:allow

// BadToken creates invalid tokens for testing.  To avoid exposing token spoofing capabilities, a limited number of
// bad token types will be supported.
func BadToken(claims *CommonClaims, flaw TokenFlaw, keyPath string) (token *jwt.Token, signedString string, err error) {
	signingKey, err := GetPrivateKey(keyPath)
	if err != nil {
		return
	}
	signingMethod := jwt.SigningMethodRS512
	tokenID := newTokenID()
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(20 * time.Minute))
	claims.ID = tokenID
	claims.Issuer = "ssas"

	switch flaw {
	case Postdated:
		claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour).Add(time.Minute))
	case Expired:
		claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
	case ExtremelyExpired:
		claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-30 * 24 * time.Hour))
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-30 * 24 * time.Hour).Add(time.Minute))
	case BadSigner:
		// No-op; the signer is managed by the caller
	case BadIssuer:
		claims.Issuer = "bad_actor"
	case MissingID:
		claims.ID = ""
	default:
		signedString = "this_is_a_bad_signed_string"
		err = errors.New("unknown token flaw")
		return
	}

	token = jwt.NewWithClaims(signingMethod, claims)
	signedString, err = token.SignedString(signingKey)
	if err != nil {
		ssas.Logger.Error("token signing error " + err.Error())
	}
	return
}

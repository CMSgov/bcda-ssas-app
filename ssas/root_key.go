package ssas

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/pborman/uuid"
	"gopkg.in/macaroon.v2"
	"gorm.io/gorm"
)

type RootKey struct {
	gorm.Model
	UUID      string `gorm:"column:uuid"`
	Key       string
	ExpiresAt time.Time
	SystemID  uint
}

type Caveats map[string]string

func NewRootKey(ctx context.Context, systemID uint, expiration time.Time) (*RootKey, error) {
	secret, err := generateRandomString()
	if err != nil {
		return nil, fmt.Errorf("failed to generate macaroon secret: %s", err.Error())
	}
	rk := &RootKey{
		UUID:      uuid.NewRandom().String(),
		Key:       secret,
		ExpiresAt: expiration,
		SystemID:  systemID,
	}

	if err := Connection.WithContext(ctx).Create(rk).Error; err != nil {
		return nil, fmt.Errorf("could not save root key: %s", err.Error())
	}
	return rk, nil
}

func (rk *RootKey) IsExpired() bool {
	return time.Now().After(rk.ExpiresAt)
}

// Generate - Generate a Macaroon from the Token configuration
func (rk *RootKey) Generate(caveats []Caveats, location string) (string, error) {
	m, err := macaroon.New([]byte(rk.Key), []byte(rk.UUID), location, macaroon.Version(cfg.GetEnvInt("SSAS_MACAROON_VERSION", 1))) // #nosec G115
	if err != nil {
		return "", fmt.Errorf("error creating new macaroon: %s", err.Error())
	}

	for _, caveat := range caveats {
		for k, v := range caveat {
			err := m.AddFirstPartyCaveat([]byte(fmt.Sprintf("%s=%s", k, v)))
			if err != nil {
				return "", fmt.Errorf("failed to add caveat: %s", err.Error())
			}
		}
	}

	b, err := m.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("error marshal-ing token: %s", err.Error())
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func generateRandomString() (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+{}[]|:;<>?,./"
	const n = 24
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

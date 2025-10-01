package ssas

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"golang.org/x/crypto/pbkdf2"
)

// Hash is a cryptographically hashed string
type Hash string

// NewHash creates a Hash value from a source string
// The HashValue consists of the salt and hash separated by a colon ( : )
// If the source of randomness fails it returns an error.
func NewHash(source string) (Hash, error) {
	if source == "" {
		return Hash(""), errors.New("empty string provided to hash function")
	}
	salt := make([]byte, cfg.HashCfg.SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return Hash(""), err
	}

	start := time.Now()
	h := pbkdf2.Key([]byte(source), salt, cfg.HashCfg.HashIter, cfg.HashCfg.HashKeyLen, sha512.New)
	hashCreationTime := time.Since(start)
	Logger.Info("elapsed: ", hashCreationTime)

	hashValue := fmt.Sprintf("%s:%s:%d", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(h), cfg.HashCfg.HashIter)
	return Hash(hashValue), nil
}

// IsHashOf accepts an unhashed string, which it first hashes and then compares to itself
func (h Hash) IsHashOf(source string) bool {
	var (
		hash, saltEnc string
		iterCount     int
		err           error
	)
	// Avoid comparing with an empty source so that a hash of an empty string is never successful
	if source == "" {
		return false
	}

	vals := strings.Split(h.String(), ":")
	switch len(vals) {
	case 2:
		saltEnc, hash = vals[0], vals[1]
		// We do not have a iteration count specified
		iterCount = cfg.HashCfg.HashIter
	case 3:
		saltEnc, hash = vals[0], vals[1]
		if iterCount, err = strconv.Atoi(vals[2]); err != nil {
			return false
		}
	default:
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(saltEnc)
	if err != nil {
		return false
	}

	sourceHash := pbkdf2.Key([]byte(source), salt, iterCount, cfg.HashCfg.HashKeyLen, sha512.New)
	return hash == base64.StdEncoding.EncodeToString(sourceHash)
}

func (h Hash) String() string {
	return string(h)
}

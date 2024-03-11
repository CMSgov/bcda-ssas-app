package ssas

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
)

var (
	hashIter   int
	hashKeyLen int
	saltSize   int
)

// Hash is a cryptographically hashed string
type Hash string

// The time for hash comparison should be about 1s.  Increase hashIter if this is significantly faster in production.
// Use the TestHashIterTime test to determine the amount required to reach 1s.
// Note that changing hashKeyLen will result in invalidating existing stored hashes (e.g. credentials).
func init() {
	if os.Getenv("DEBUG") == "true" {
		hashIter = cfg.GetEnvInt("SSAS_HASH_ITERATIONS", 130000)
		hashKeyLen = cfg.GetEnvInt("SSAS_HASH_KEY_LENGTH", 64)
		saltSize = cfg.GetEnvInt("SSAS_HASH_SALT_SIZE", 32)
	} else {
		hashIter = cfg.GetEnvInt("SSAS_HASH_ITERATIONS", 0)
		hashKeyLen = cfg.GetEnvInt("SSAS_HASH_KEY_LENGTH", 0)
		saltSize = cfg.GetEnvInt("SSAS_HASH_SALT_SIZE", 0)
	}

	if hashIter == 0 || hashKeyLen == 0 || saltSize == 0 {
		helpMsg := "SSAS_HASH_ITERATIONS, SSAS_HASH_KEY_LENGTH and SSAS_HASH_SALT_SIZE environment values must be set"
		Logger.WithFields(logrus.Fields{"Help": helpMsg}).Info(logrus.WithField("Event", "ServiceHalted"))
		panic(helpMsg)
	}
}

// NewHash creates a Hash value from a source string
// The HashValue consists of the salt and hash separated by a colon ( : )
// If the source of randomness fails it returns an error.
func NewHash(source string) (Hash, error) {
	if source == "" {
		return Hash(""), errors.New("empty string provided to hash function")
	}

	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return Hash(""), err
	}

	start := time.Now()
	h := pbkdf2.Key([]byte(source), salt, hashIter, hashKeyLen, sha512.New)
	hashCreationTime := time.Since(start)
	Logger.Info(logrus.Fields{"Elapsed": hashCreationTime, "Event": "SecureHashTime"})

	hashValue := fmt.Sprintf("%s:%s:%d", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(h), hashIter)
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
		iterCount = hashIter
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

	sourceHash := pbkdf2.Key([]byte(source), salt, iterCount, hashKeyLen, sha512.New)
	return hash == base64.StdEncoding.EncodeToString(sourceHash)
}

func (h Hash) String() string {
	return string(h)
}

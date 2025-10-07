package cfg

import (
	"fmt"
	"go/build"
	"os"
	"time"

	"github.com/joho/godotenv"
)

var (
	DefaultScope                  string
	MaxIPs                        int
	CredentialExpiration          time.Duration
	MacaroonExpiration            time.Duration
	HashIter                      int
	HashKeyLen                    int
	SaltSize                      int
	SelfRegistrationTokenDuration time.Duration
)

// Get configuration/environment variables for Hashes and Systems.
func LoadEnvConfigs() {
	env := os.Getenv("DEPLOYMENT_TARGET")
	if env == "" {
		env = "local"
	}
	gopath := os.Getenv("GOPATH")

	if gopath == "" {
		gopath = build.Default.GOPATH
		//when GOROOT==gopath, it'll still be empty. Thus, we specify what's in our Dockerfile.
		if gopath == "" {
			gopath = "/go"
		}
	}

	envPath := fmt.Sprintf(gopath+"/src/github.com/CMSgov/bcda-ssas-app/ssas/cfg/configs/%s.env", env)
	err := godotenv.Load(envPath)
	if err != nil {
		msg := fmt.Sprintf("Unable to load environment variables in env %s; message: %s", env, err.Error())
		panic(msg)
	}

	DefaultScope = os.Getenv("SSAS_DEFAULT_SYSTEM_SCOPE")
	if DefaultScope == "" {
		panic("Unable to source default system scope; check env files")
	}

	expirationDays := GetEnvInt("SSAS_CRED_EXPIRATION_DAYS", 90)
	CredentialExpiration = time.Duration(expirationDays*24) * time.Hour
	MaxIPs = GetEnvInt("SSAS_MAX_SYSTEM_IPS", 8)
	macaroonExpirationDays := GetEnvInt("SSAS_MACAROON_EXPIRATION_DAYS", 365)
	MacaroonExpiration = time.Duration(macaroonExpirationDays*24) * time.Hour

	if os.Getenv("DEBUG") == "true" {
		HashIter = GetEnvInt("SSAS_HASH_ITERATIONS", 130000)
		HashKeyLen = GetEnvInt("SSAS_HASH_KEY_LENGTH", 64)
		SaltSize = GetEnvInt("SSAS_HASH_SALT_SIZE", 32)
	} else {
		HashIter = GetEnvInt("SSAS_HASH_ITERATIONS", 0)
		HashKeyLen = GetEnvInt("SSAS_HASH_KEY_LENGTH", 0)
		SaltSize = GetEnvInt("SSAS_HASH_SALT_SIZE", 0)
	}

	if HashIter == 0 || HashKeyLen == 0 || SaltSize == 0 {
		// ServiceHalted(Event{Help:"SSAS_HASH_ITERATIONS, SSAS_HASH_KEY_LENGTH and SSAS_HASH_SALT_SIZE environment values must be set"})
		panic("SSAS_HASH_ITERATIONS, SSAS_HASH_KEY_LENGTH and SSAS_HASH_SALT_SIZE environment values must be set")
	}

	minutes := GetEnvInt("SSAS_MFA_TOKEN_TIMEOUT_MINUTES", 60)
	SelfRegistrationTokenDuration = time.Duration(int64(time.Minute) * int64(minutes))
}

package cfg

import (
	"fmt"
	"go/build"
	"os"
	"time"

	"github.com/joho/godotenv"
)

var (
	SystemCfg *SystemsConfig
	HashCfg   *HashConfig
)

// Get configuration/environment variables for Hashes and Systems.
func LoadEnvConfigs() {
	SystemCfg = loadSystemConfig()
	HashCfg = loadHashConfig()
}

type SystemsConfig struct {
	DefaultScope         string
	MaxIPs               int
	CredentialExpiration time.Duration
	MacaroonExpiration   time.Duration
}

func loadSystemConfig() *SystemsConfig {
	sysCfg := &SystemsConfig{}
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

	sysCfg.DefaultScope = os.Getenv("SSAS_DEFAULT_SYSTEM_SCOPE")
	if sysCfg.DefaultScope == "" {
		panic("Unable to source default system scope; check env files")
	}

	expirationDays := GetEnvInt("SSAS_CRED_EXPIRATION_DAYS", 90)
	sysCfg.CredentialExpiration = time.Duration(expirationDays*24) * time.Hour
	sysCfg.MaxIPs = GetEnvInt("SSAS_MAX_SYSTEM_IPS", 8)
	macaroonExpirationDays := GetEnvInt("SSAS_MACAROON_EXPIRATION_DAYS", 365)
	sysCfg.MacaroonExpiration = time.Duration(macaroonExpirationDays*24) * time.Hour

	return sysCfg
}

type HashConfig struct {
	HashIter   int
	HashKeyLen int
	SaltSize   int
}

// loadHashConfig will set environment variables needed for creating a Hash.
func loadHashConfig() *HashConfig {
	hashCfg := &HashConfig{}
	if os.Getenv("DEBUG") == "true" {
		hashCfg.HashIter = GetEnvInt("SSAS_HASH_ITERATIONS", 130000)
		hashCfg.HashKeyLen = GetEnvInt("SSAS_HASH_KEY_LENGTH", 64)
		hashCfg.SaltSize = GetEnvInt("SSAS_HASH_SALT_SIZE", 32)
	} else {
		hashCfg.HashIter = GetEnvInt("SSAS_HASH_ITERATIONS", 0)
		hashCfg.HashKeyLen = GetEnvInt("SSAS_HASH_KEY_LENGTH", 0)
		hashCfg.SaltSize = GetEnvInt("SSAS_HASH_SALT_SIZE", 0)
	}

	if hashCfg.HashIter == 0 || hashCfg.HashKeyLen == 0 || hashCfg.SaltSize == 0 {
		// ServiceHalted(Event{Help:"SSAS_HASH_ITERATIONS, SSAS_HASH_KEY_LENGTH and SSAS_HASH_SALT_SIZE environment values must be set"})
		panic("SSAS_HASH_ITERATIONS, SSAS_HASH_KEY_LENGTH and SSAS_HASH_SALT_SIZE environment values must be set")
	}
	return hashCfg
}

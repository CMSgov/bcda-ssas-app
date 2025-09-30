package cfg

import (
	"fmt"
	"go/build"
	"os"
	"time"

	"github.com/joho/godotenv"
)

// SystemCfg is used to retrieve environment or configuration values. Set in main().
var SystemCfg *SystemsConfig

// HashCfg is used to retrieve environment or configuration values. Set in main().
var HashCfg *HashConfig

type Config struct {
	Systems SystemsConfig
	Hash    HashConfig
}

func NewConfig() *Config {
	return &Config{Systems: *NewSystemsConfig()}
}

type SystemsConfig struct {
	DefaultScope         string
	MaxIPs               int
	CredentialExpiration time.Duration
	MacaroonExpiration   time.Duration
}

func NewSystemsConfig() *SystemsConfig {
	sysConfig := &SystemsConfig{}
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

	sysConfig.DefaultScope = os.Getenv("SSAS_DEFAULT_SYSTEM_SCOPE")
	if sysConfig.DefaultScope == "" {
		panic("Unable to source default system scope; check env files")
	}

	expirationDays := GetEnvInt("SSAS_CRED_EXPIRATION_DAYS", 90)
	sysConfig.CredentialExpiration = time.Duration(expirationDays*24) * time.Hour
	sysConfig.MaxIPs = GetEnvInt("SSAS_MAX_SYSTEM_IPS", 8)
	macaroonExpirationDays := GetEnvInt("SSAS_MACAROON_EXPIRATION_DAYS", 365)
	sysConfig.MacaroonExpiration = time.Duration(macaroonExpirationDays*24) * time.Hour

	return sysConfig
}

type HashConfig struct {
	HashIter   int
	HashKeyLen int
	SaltSize   int
}

// SetHashConfig will set environment variables needed for creating a Hash.
func SetHashConfig() {
	HashCfg = &HashConfig{}
	if os.Getenv("DEBUG") == "true" {
		HashCfg.HashIter = GetEnvInt("SSAS_HASH_ITERATIONS", 130000)
		HashCfg.HashKeyLen = GetEnvInt("SSAS_HASH_KEY_LENGTH", 64)
		HashCfg.SaltSize = GetEnvInt("SSAS_HASH_SALT_SIZE", 32)
	} else {
		HashCfg.HashIter = GetEnvInt("SSAS_HASH_ITERATIONS", 0)
		HashCfg.HashKeyLen = GetEnvInt("SSAS_HASH_KEY_LENGTH", 0)
		HashCfg.SaltSize = GetEnvInt("SSAS_HASH_SALT_SIZE", 0)
	}

	if HashCfg.HashIter == 0 || HashCfg.HashKeyLen == 0 || HashCfg.SaltSize == 0 {
		// ServiceHalted(Event{Help:"SSAS_HASH_ITERATIONS, SSAS_HASH_KEY_LENGTH and SSAS_HASH_SALT_SIZE environment values must be set"})
		panic("SSAS_HASH_ITERATIONS, SSAS_HASH_KEY_LENGTH and SSAS_HASH_SALT_SIZE environment values must be set")
	}
}

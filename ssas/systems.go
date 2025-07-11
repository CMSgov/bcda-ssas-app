package ssas

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"go/build"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/joho/godotenv"
	"github.com/pborman/uuid"
	"gorm.io/gorm"
)

var DefaultScope string
var MaxIPs int
var CredentialExpiration time.Duration
var MacaroonExpiration time.Duration

func init() {
	getEnvVars()
}

func getEnvVars() {
	env := os.Getenv("DEPLOYMENT_TARGET")
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
		Logger.Fatal(msg)
		panic(msg)
	}
	DefaultScope = os.Getenv("SSAS_DEFAULT_SYSTEM_SCOPE")
	if DefaultScope == "" {
		panic("Unable to source default system scope; check env files")
	}

	expirationDays := cfg.GetEnvInt("SSAS_CRED_EXPIRATION_DAYS", 90)
	CredentialExpiration = time.Duration(expirationDays*24) * time.Hour
	MaxIPs = cfg.GetEnvInt("SSAS_MAX_SYSTEM_IPS", 8)
	macaroonExpirationDays := cfg.GetEnvInt("SSAS_MACAROON_EXPIRATION_DAYS", 365)
	MacaroonExpiration = time.Duration(macaroonExpirationDays*24) * time.Hour
}

type System struct {
	gorm.Model
	GID            uint            `json:"g_id"`
	GroupID        string          `json:"group_id"`
	ClientID       string          `json:"client_id"`
	SoftwareID     string          `json:"software_id"`
	ClientName     string          `json:"client_name"`
	APIScope       string          `json:"api_scope"`
	EncryptionKeys []EncryptionKey `json:"encryption_keys,omitempty"`
	Secrets        []Secret        `json:"secrets,omitempty"`
	LastTokenAt    time.Time       `json:"last_token_at"`
	XData          string          `json:"xdata"`
	SGAKey         string          `json:"sga_key"`
}

type EncryptionKey struct {
	gorm.Model
	Body     string `json:"body"`
	System   System `gorm:"foreignkey:SystemID;association_foreignkey:ID"`
	SystemID uint   `json:"system_id"`
	UUID     string `json:"uuid,omitempty"`
}

type Secret struct {
	gorm.Model
	Hash     string `json:"hash"`
	System   System `gorm:"foreignkey:SystemID;association_foreignkey:ID"`
	SystemID uint   `json:"system_id"`
}

type ClientToken struct {
	gorm.Model
	Label     string    `json:"label"`
	Uuid      string    `json:"uuid"`
	System    System    `gorm:"foreignkey:SystemID;association_foreignkey:ID"`
	SystemID  uint      `json:"system_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

/*
SaveClientToken should be provided with a token label and token uuid, which will
be saved to the client tokens table and associated with the current system.
*/
func (system *System) SaveClientToken(ctx context.Context, label string, groupXData string, expiration time.Time) (*ClientToken, string, error) {
	rk, err := NewRootKey(ctx, system.ID, expiration)
	if err != nil {
		return nil, "", fmt.Errorf("could not create a root key for macaroon generation for clientID %s: %s", system.ClientID, err.Error())
	}

	caveats := make([]Caveats, 4)
	caveats[0] = map[string]string{"expiration": rk.ExpiresAt.Format(time.RFC3339)}
	caveats[1] = map[string]string{"system_id": strconv.FormatUint(uint64(system.ID), 10)}
	caveats[2] = map[string]string{"group_data": base64.StdEncoding.EncodeToString([]byte(groupXData))}
	if system.XData != "" {
		caveats[3] = map[string]string{"system_data": base64.StdEncoding.EncodeToString([]byte(system.XData))}
	}

	token, _ := rk.Generate(caveats, cfg.FromEnv("SSAS_MACAROON_LOCATION", "localhost"))
	ct := ClientToken{
		Label:     label,
		Uuid:      rk.UUID,
		SystemID:  system.ID,
		ExpiresAt: rk.ExpiresAt,
	}

	if err := Connection.WithContext(ctx).Create(&ct).Error; err != nil {
		return nil, "", fmt.Errorf("could not save client token for clientID %s: %s", system.ClientID, err.Error())
	}
	return &ct, token, nil
}

func (system *System) GetClientTokens(ctx context.Context) ([]ClientToken, error) {
	var tokens []ClientToken
	err := Connection.WithContext(ctx).Find(&tokens, "system_id=? AND deleted_at IS NULL", system.ID).Error
	if err != nil {
		return tokens, err
	}
	return tokens, nil
}

func (system *System) DeleteClientToken(ctx context.Context, tokenID string) error {
	tx := Connection.WithContext(ctx).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	var rk RootKey
	tx.Where("uuid = ? AND system_id = ?", tokenID, system.ID).Find(&rk)
	tx.Where("uuid = ?", rk.UUID).Delete(&ClientToken{})
	tx.Delete(&rk)
	err := tx.Commit().Error
	if err != nil {
		tx.Rollback()
	}
	return err
}

// IsExpired tests whether this secret has expired
func (secret *Secret) IsExpired() bool {
	return secret.UpdatedAt.Add(CredentialExpiration).Before(time.Now())
}

type IP struct {
	gorm.Model
	Address  string
	SystemID uint
}

type AuthRegData struct {
	GroupID         string
	AllowedGroupIDs []string
	OktaID          string
}

/*
SaveSecret should be provided with a secret hashed with ssas.NewHash(), which will
be saved to the secrets table and associated with the current system.
*/
func (system *System) SaveSecret(ctx context.Context, hashedSecret string) error {
	secret := Secret{
		Hash:     hashedSecret,
		SystemID: system.ID,
	}

	if err := system.deactivateSecrets(ctx); err != nil {
		return err
	}

	if err := Connection.WithContext(ctx).Create(&secret).Error; err != nil {
		return fmt.Errorf("could not save secret for clientID %s: %s", system.ClientID, err.Error())
	}

	return nil
}

/*
GetSecret will retrieve the hashed secret associated with the current system.
*/
func (system *System) GetSecret(ctx context.Context) (Secret, error) {
	secret := Secret{}
	err := Connection.WithContext(ctx).Where("system_id = ?", system.ID).First(&secret).Error
	if err != nil {
		return secret, fmt.Errorf("unable to get hashed secret for clientID %s: %s", system.ClientID, err.Error())
	}

	if strings.TrimSpace(secret.Hash) == "" {
		return secret, fmt.Errorf("stored hash of secret for clientID %s is blank", system.ClientID)
	}

	return secret, nil
}

// SaveTokenTime puts the current time in systems.last_token_at
func (system *System) SaveTokenTime(ctx context.Context) (err error) {
	err = Connection.WithContext(ctx).Model(&system).UpdateColumn("last_token_at", time.Now()).Error
	if err != nil {
		return err
	}
	return nil
}

/*
RevokeSecret revokes a system's secret
*/
func (system *System) RevokeSecret(ctx context.Context, systemID string) error {
	_, err := XDataFor(ctx, *system)
	if err != nil {
		return fmt.Errorf("could not get group XData for clientID %s: %s", system.ClientID, err.Error())
	}

	err = system.deactivateSecrets(ctx)
	if err != nil {
		return fmt.Errorf("unable to revoke credentials for clientID %s", system.ClientID)
	}
	return nil
}

/*
DeactivateSecrets soft deletes secrets associated with the system.
*/
func (system *System) deactivateSecrets(ctx context.Context) error {
	err := Connection.WithContext(ctx).Where("system_id = ?", system.ID).Delete(&Secret{}).Error
	if err != nil {
		return fmt.Errorf("unable to soft delete previous secrets for clientID %s: %s", system.ClientID, err.Error())
	}
	return nil
}

/*
GetEncryptionKey retrieves the key associated with the current system.
*/
func (system *System) GetEncryptionKey(ctx context.Context) (EncryptionKey, error) {
	var encryptionKey EncryptionKey
	err := Connection.WithContext(ctx).First(&encryptionKey, "system_id = ?", system.ID).Error
	if err != nil {
		return encryptionKey, fmt.Errorf("cannot find key for clientID %s: %s", system.ClientID, err.Error())
	}
	return encryptionKey, nil
}

/*
FindEncryptionKey retrieves the key by id associated with the current system.
*/
func (system *System) FindEncryptionKey(ctx context.Context, trackingID string, keyId string) (EncryptionKey, error) {
	var encryptionKey EncryptionKey
	err := Connection.WithContext(ctx).First(&encryptionKey, "system_id = ? AND uuid=?", system.ID, keyId).Error
	if err != nil {
		return encryptionKey, fmt.Errorf("cannot find key for systemId %d: and keyId: %s error: %s", system.ID, keyId, err.Error())
	}

	return encryptionKey, nil
}

/*
GetEncryptionKeys retrieves the keys associated with the current system.
*/
func (system *System) GetEncryptionKeys(ctx context.Context) ([]EncryptionKey, error) {
	var encryptionKeys []EncryptionKey
	err := Connection.WithContext(ctx).Where("system_id = ?", system.ID).Find(&encryptionKeys).Error
	if err != nil {
		return encryptionKeys, fmt.Errorf("cannot find key for clientID %s: %s", system.ClientID, err.Error())
	}

	return encryptionKeys, nil
}

/*
DeleteEncryptionKey deletes the key associated with the current system.
*/
func (system *System) DeleteEncryptionKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("requires keyID to delete key for clientID %s", system.ClientID)
	}
	var encryptionKey EncryptionKey
	err := Connection.WithContext(ctx).Where("system_id = ? AND uuid = ?", system.ID, keyID).Delete(&encryptionKey).Error
	if err != nil {
		return fmt.Errorf("cannot find key to delete for clientID %s: %s", system.ClientID, err.Error())
	}

	return nil
}

/*
SavePublicKey should be provided with a public key in PEM format, which will be saved
to the encryption_keys table and associated with the current system.
*/
func (system *System) SavePublicKey(publicKey io.Reader, signature string) (*EncryptionKey, error) {
	return system.SavePublicKeyDB(publicKey, signature, true, Connection)
}

func (system *System) SavePublicKeyDB(publicKey io.Reader, signature string, onlyOne bool, db *gorm.DB) (*EncryptionKey, error) {
	k, err := io.ReadAll(publicKey)
	if err != nil {
		return nil, fmt.Errorf("cannot read public key for clientID %s: %s", system.ClientID, err.Error())
	}

	key, err := ReadPublicKey(string(k))
	if err != nil {
		return nil, fmt.Errorf("invalid public key for clientID %s: %s", system.ClientID, err.Error())
	}
	if key == nil {
		return nil, fmt.Errorf("invalid public key for clientID %s", system.ClientID)
	}

	if signature != "" {
		if err := VerifySignature(key, signature); err != nil {
			return nil, fmt.Errorf("invalid signature for clientID %s", system.ClientID)
		}
	}

	encryptionKey := EncryptionKey{
		UUID:     uuid.NewRandom().String(),
		Body:     string(k),
		SystemID: system.ID,
	}

	if onlyOne {
		// Only one key should be valid per system.  Soft delete the currently active key, if any.
		err = db.Where("system_id = ?", system.ID).Delete(&EncryptionKey{}).Error
		if err != nil {
			return nil, fmt.Errorf("unable to soft delete previous encryption keys for clientID %s: %s", system.ClientID, err.Error())
		}
	}

	err = db.Create(&encryptionKey).Error
	if err != nil {
		return nil, fmt.Errorf("could not save public key for clientID %s: %s", system.ClientID, err.Error())
	}

	return &encryptionKey, nil
}

func (system *System) AddAdditionalPublicKey(publicKey io.Reader, signature string) (*EncryptionKey, error) {
	return system.SavePublicKeyDB(publicKey, signature, false, Connection)
}

type Credentials struct {
	ClientID     string    `json:"client_id,omitempty"`
	ClientSecret string    `json:"client_secret,omitempty"`
	ClientToken  string    `json:"client_token,omitempty"`
	SystemID     string    `json:"system_id"`
	ClientName   string    `json:"client_name"`
	IPs          []string  `json:"ips,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	XData        string    `json:"xdata,omitempty"`
	PublicKeyID  string    `json:"public_key_id"`
}

/*
RegisterSystem will save a new system and public key after verifying provided details for validity.  It returns
a ssas.Credentials struct including the generated clientID and secret.
*/
func RegisterSystem(ctx context.Context, clientName string, groupID string, scope string, publicKeyPEM string, ips []string, trackingID string) (Credentials, error) {
	systemInput := SystemInput{
		ClientName: clientName,
		GroupID:    groupID,
		Scope:      scope,
		PublicKey:  publicKeyPEM,
		IPs:        ips,
		XData:      "",
		TrackingID: trackingID,
	}
	return registerSystem(ctx, systemInput, false)
}

func RegisterV2System(ctx context.Context, input SystemInput) (Credentials, error) {
	return registerSystem(ctx, input, true)
}

func registerSystem(ctx context.Context, input SystemInput, isV2 bool) (Credentials, error) {
	// The public key and hashed secret are stored separately in the encryption_keys and secrets tables, requiring
	// multiple INSERT statements.  To ensure we do not get into an invalid state, wrap the two INSERT statements in a transaction.
	tx := Connection.WithContext(ctx).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	creds := Credentials{}
	clientID := uuid.NewRandom().String()

	if input.ClientName == "" {
		return creds, errors.New("clientName is required")
	}

	if isV2 && input.PublicKey == "" {
		return creds, errors.New("public key is required")
	}

	scope := input.Scope

	if scope == "" {
		scope = DefaultScope
	} else if input.Scope != DefaultScope {
		return creds, errors.New("scope must be: " + DefaultScope)
	}

	group, err := GetGroupByGroupID(ctx, input.GroupID)

	if err != nil {
		return creds, errors.New("unable to find group with id " + input.GroupID)
	}

	system := System{
		GID:        group.ID,
		GroupID:    input.GroupID,
		ClientID:   clientID,
		ClientName: input.ClientName,
		APIScope:   scope,
		XData:      input.XData,
	}

	err = tx.Create(&system).Error

	if err != nil {
		errmsg := fmt.Sprintf("could not save system for clientID %s, groupID %s: %s", clientID, input.GroupID, err.Error())
		return creds, errors.New(errmsg)
	}

	for _, address := range input.IPs {
		if !ValidAddress(address) {
			tx.Rollback()
			errmsg := fmt.Sprintf("invalid IP %s", address)
			return creds, errors.New(errmsg)
		}

		ip := IP{
			Address:  address,
			SystemID: system.ID,
		}

		err = tx.Create(&ip).Error
		if err != nil {
			tx.Rollback()
			errmsg := fmt.Sprintf("could not save IP %s; %s", address, err.Error())
			return creds, errors.New(errmsg)
		}
	}

	if input.PublicKey != "" {
		key, err := system.SavePublicKeyDB(strings.NewReader(input.PublicKey), input.Signature, !isV2, tx)
		if err != nil {
			tx.Rollback()
			return creds, err
		}
		creds.PublicKeyID = key.UUID
	}

	if isV2 {
		expiration := time.Now().Add(MacaroonExpiration)
		_, ct, err := system.SaveClientToken(ctx, "Initial Token", group.XData, expiration)
		if err != nil {
			tx.Rollback()
			errmsg := fmt.Sprintf("could not save client token for clientID %s, groupID %s: %s", clientID, input.GroupID, err.Error())
			return creds, errors.New(errmsg)
		}
		creds.ClientToken = ct
		creds.ExpiresAt = expiration
		creds.XData = system.XData
	} else {
		clientSecret, err := GenerateSecret()
		if err != nil {
			tx.Rollback()
			errmsg := fmt.Sprintf("cannot generate secret for clientID %s: %s", system.ClientID, err.Error())
			return creds, errors.New(errmsg)
		}

		hashedSecret, err := NewHash(clientSecret)
		if err != nil {
			tx.Rollback()
			errmsg := fmt.Sprintf("cannot generate hash of secret for clientID %s: %s", system.ClientID, err.Error())
			return creds, errors.New(errmsg)
		}

		secret := Secret{
			Hash:     hashedSecret.String(),
			SystemID: system.ID,
		}

		err = tx.Create(&secret).Error
		if err != nil {
			tx.Rollback()
			errmsg := fmt.Sprintf("cannot save secret for clientID %s: %s", system.ClientID, err.Error())
			return creds, errors.New(errmsg)
		}
		creds.ClientSecret = clientSecret
		creds.ExpiresAt = time.Now().Add(CredentialExpiration)
	}

	err = tx.Commit().Error
	if err != nil {
		errmsg := fmt.Sprintf("could not commit transaction for new system with groupID %s: %s", input.GroupID, err.Error())
		return creds, errors.New(errmsg)
	}

	creds.SystemID = fmt.Sprint(system.ID)
	creds.ClientName = system.ClientName
	creds.ClientID = system.ClientID
	creds.IPs = input.IPs

	return creds, nil
}

func VerifySignature(pubKey *rsa.PublicKey, signatureStr string) error {
	snippet := "This is the snippet used to verify a key pair."

	signature, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return err
	}

	hash := sha256.Sum256([]byte(snippet))
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return err
	}

	return nil
}

func (system *System) RegisterIP(ctx context.Context, address string) (IP, error) {
	if !ValidAddress(address) {
		return IP{}, errors.New("invalid ip address")
	}

	ip := IP{
		Address:  address,
		SystemID: uint(system.ID),
	}
	count := int64(0)
	Connection.WithContext(ctx).Model(&IP{}).Where("ips.system_id = ? AND ips.address = ? AND ips.deleted_at IS NULL", system.ID, address).Count(&count)
	if count != 0 {
		return IP{}, fmt.Errorf("can not create duplicate IP address:  %s for system %d", address, system.ID)
	}

	count = int64(0)
	Connection.WithContext(ctx).Model(&IP{}).Where("ips.system_id = ? AND ips.deleted_at IS NULL", system.ID).Count(&count)
	if count >= int64(MaxIPs) {
		return IP{}, fmt.Errorf("could not add ip, max number of ips reached. Max %d", count)
	}
	err := Connection.WithContext(ctx).Create(&ip).Error
	if err != nil {
		return IP{}, fmt.Errorf("could not save IP %s; %s", address, err.Error())
	}
	return ip, nil
}

func UpdateSystem(ctx context.Context, id string, v map[string]string) (System, error) {
	sys, err := GetSystemByID(ctx, id)
	if err != nil {
		return System{}, fmt.Errorf("record not found for id=%s", id)
	}

	scope, ok := v["api_scope"]
	if ok {
		sys.APIScope = scope
	}

	cn, ok := v["client_name"]
	if ok {
		sys.ClientName = cn
	}

	si, ok := v["software_id"]
	if ok {
		sys.SoftwareID = si
	}

	err = Connection.WithContext(ctx).Save(&sys).Error
	if err != nil {
		return System{}, fmt.Errorf("failed to update system: %s", err)
	}

	return sys, nil
}

func (system *System) GetIps(ctx context.Context) ([]IP, error) {
	var ips []IP
	err := Connection.WithContext(ctx).Find(&ips, "system_id=? AND deleted_at IS NULL", system.ID).Error
	if err != nil {
		return ips, err
	}
	return ips, nil
}

// DeleteIP soft-deletes an IP associated with a specific system
func (system *System) DeleteIP(ctx context.Context, ipID string) error {
	var (
		ip  IP
		err error
	)

	// Find IP to delete
	err = Connection.WithContext(ctx).First(&ip, "system_id = ? AND id = ?", system.ID, ipID).Error
	if err != nil {
		return fmt.Errorf("failed to get ip address with ID %s: %s", ipID, err)
	}

	// Soft delete IP
	// Note: db.Delete() soft-deletes by default because the DeletedAt field is set on the Gorm model that IP inherits
	err = Connection.WithContext(ctx).Delete(&ip).Error
	if err != nil {
		return fmt.Errorf("failed to delete IP address with ID %s: %s", ipID, err)
	}

	return nil
}

// DataForSystem returns the group extra data associated with this system
func XDataFor(ctx context.Context, system System) (string, error) {
	if system.GID > math.MaxInt {
		return "", fmt.Errorf("group id uint overflow converting to int")
	}
	group, err := GetGroupByID(ctx, strconv.Itoa(int(system.GID)))
	if err != nil {
		return "", fmt.Errorf("no group for system %d; %s", system.ID, err)
	}
	return group.XData, nil
}

// GetSystemsByGroupIDString returns the systems associated with the provided groups.group_id
func GetSystemsByGroupIDString(ctx context.Context, groupId string) ([]System, error) {
	var (
		systems []System
		err     error
	)

	if err = Connection.WithContext(ctx).Where("group_id = ? AND deleted_at IS NULL", groupId).Find(&systems).Error; err != nil {
		err = fmt.Errorf("no Systems found with group_id %s", groupId)
	}
	return systems, err
}

// GetSystemByClientID returns the system associated with the provided clientID
func GetSystemByClientID(ctx context.Context, clientID string) (System, error) {
	var (
		system System
		err    error
	)

	if err = Connection.WithContext(ctx).First(&system, "client_id = ?", clientID).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		err = fmt.Errorf("no System record found for client %s", clientID)
	}
	return system, err
}

// GetSystemByID returns the system associated with the provided ID
func GetSystemByID(ctx context.Context, id string) (System, error) {
	var (
		system System
		err    error
	)

	id1, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return System{}, fmt.Errorf("invalid input %s; %s", id, err)
	}

	if err = Connection.WithContext(ctx).First(&system, id1).Error; err != nil {
		err = fmt.Errorf("no System record found with ID %s %v", id, err)
	}
	return system, err
}

func GenerateSecret() (string, error) {
	b := make([]byte, 40)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}

func GetAllIPs() ([]string, error) {
	var (
		ips []string
		err error
	)

	// Only include addresses registered to active, unexpired systems
	where := "deleted_at IS NULL AND system_id IN (SELECT systems.id FROM secrets JOIN systems ON secrets.system_id = systems.id JOIN groups ON systems.g_id = groups.id " +
		"WHERE secrets.deleted_at IS NULL AND systems.deleted_at IS NULL AND groups.deleted_at IS NULL AND secrets.updated_at > ?)"
	exp := time.Now().Add(-1 * CredentialExpiration)

	if err = Connection.Order("address").Model(&IP{}).Where(where, exp).Distinct("address").Pluck(
		"address", &ips).Error; err != nil {
		err = fmt.Errorf("no IP's found: %s", err.Error())
	}
	return ips, err
}

func (system *System) GetIPs() ([]string, error) {
	var (
		ips []string
		err error
	)

	if err = Connection.Model(&IP{}).Where("system_id = ? AND deleted_at IS NULL", system.ID).Pluck("address", &ips).Error; err != nil {
		err = fmt.Errorf("no IP's found with system_id %d: %s", system.ID, err.Error())
	}
	return ips, err
}

func (system *System) GetIPsData(ctx context.Context) ([]IP, error) {
	var (
		ips []IP
		err error
	)

	if err = Connection.WithContext(ctx).Find(&ips, "system_id = ? AND deleted_at IS NULL", system.ID).Error; err != nil {
		err = fmt.Errorf("no IP's found with system_id %d: %s", system.ID, err.Error())
	}
	return ips, err
}

// ResetSecret creates a new secret for the current system.
func (system *System) ResetSecret(ctx context.Context) (Credentials, error) {
	creds := Credentials{}

	_, err := XDataFor(ctx, *system)
	if err != nil {
		return creds, fmt.Errorf("could not get group XData for clientID %s: %s", system.ClientID, err.Error())
	}

	secretString, err := GenerateSecret()
	if err != nil {
		return creds, fmt.Errorf("could not reset secret for clientID %s: %s", system.ClientID, err.Error())
	}

	hashedSecret, err := NewHash(secretString)
	if err != nil {
		return creds, fmt.Errorf("could not reset secret for clientID %s: %s", system.ClientID, err.Error())
	}

	hashedSecretString := hashedSecret.String()
	if err = system.SaveSecret(ctx, hashedSecretString); err != nil {
		return creds, fmt.Errorf("could not reset secret for clientID %s: %s", system.ClientID, err.Error())
	}

	creds.SystemID = fmt.Sprint(system.ID)
	creds.ClientID = system.ClientID
	creds.ClientSecret = secretString
	creds.ClientName = system.ClientName
	creds.ExpiresAt = time.Now().Add(CredentialExpiration)
	return creds, nil
}

// The following code is a bit confusing.  It first checks a valid IP address, if fails, returns false.
// It then checks if the found IP address is in a reserved range.  If it is return false.
// At a glance this code seems like it allows for an IP address OR a CIDR range to be passed in
// but that is not the case.  We actually do NOT want SGAs to be able
// to send us CIDR ranges.  They could accidentally open up huge ranges of IP addresses.
func ValidAddress(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}

	// Source https://en.wikipedia.org/wiki/Reserved_IP_addresses
	// #SonarIgnore--BEGIN
	// SonarQube does not like hard-coded IP's or CIDR's, but these are not intended to be configurable
	badNetworks := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",
		"::/128",
		"::1/128",
		"2001:db8::/32",
		"2002::/16",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	// #SonarIgnore--END
	for _, network := range badNetworks {
		_, ipNet, _ := net.ParseCIDR(network)
		if ipNet.Contains(ip) {
			return false
		}
	}

	return true
}

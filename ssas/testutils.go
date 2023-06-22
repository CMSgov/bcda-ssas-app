package ssas

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"testing"

	"github.com/pborman/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func ResetAdminCreds() (encSecret string, err error) {
	err = RevokeActiveCreds("admin")
	if err != nil {
		return
	}

	id := "31e029ef-0e97-47f8-873c-0e8b7e7f99bf"
	system, err := GetSystemByClientID(context.Background(), id)
	if err != nil {
		return
	}

	creds, err := system.ResetSecret(context.Background(), id)
	if err != nil {
		return
	}

	basicAuth := id + ":" + creds.ClientSecret
	encSecret = base64.StdEncoding.EncodeToString([]byte(basicAuth))

	return
}

func ExpireAdminCreds() {
	Connection.Exec("UPDATE secrets SET created_at = '2000-01-01', updated_at = '2000-01-01' WHERE system_id IN (SELECT id FROM systems WHERE client_id = '31e029ef-0e97-47f8-873c-0e8b7e7f99bf')")
}

func GeneratePublicKey(bits int) (string, string, *rsa.PrivateKey, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", nil, fmt.Errorf("unable to generate keyPair: %s", err.Error())
	}

	publicKeyPKIX, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		return "", "", nil, fmt.Errorf("unable to marshal public key: %s", err.Error())
	}

	publicKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPKIX,
	})

	hash := sha256.Sum256([]byte("This is the snippet used to verify a key pair."))
	b, err := keyPair.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to verify signature with public key: %s", err.Error())
	}
	return string(publicKeyBytes), base64.StdEncoding.EncodeToString(b), keyPair, nil
}

func RandomHexID() string {
	b, err := someRandomBytes(4)
	if err != nil {
		return "not_a_random_client_id"
	}
	return fmt.Sprintf("%x", b)
}

func RandomBase64(n int) string {
	b, err := someRandomBytes(20)
	if err != nil {
		return "not_a_random_base_64_string"
	}
	return base64.StdEncoding.EncodeToString(b)
}

func RandomIPv4() string {
	size := 4
	ip, err := someRandomBytes(size)
	if err != nil {
		return "not_a_random_IP_v4_address"
	}
	// We want an IP that will pass our validation tests.  Iterate until we find one.
	IPcandidate := net.IP(ip).To4().String()
	if !ValidAddress(IPcandidate) {
		return RandomIPv4()
	}
	return IPcandidate
}

func RandomIPv6() string {
	size := 16
	ip, err := someRandomBytes(size)
	if err != nil {
		return "not_a_random_IP_v6_address"
	}
	IPcandidate := net.IP(ip).To16().String()
	if !ValidAddress(IPcandidate) {
		return RandomIPv6()
	}
	return IPcandidate
}

func someRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func CreateTestXData(t *testing.T, db *gorm.DB) (creds Credentials, group Group) {
	groupID := RandomHexID()[0:4]

	group = Group{GroupID: groupID, XData: `{"group":"1"}`}
	err := db.Create(&group).Error
	require.Nil(t, err)

	_, pubKey, err := GenerateTestKeys(2048)
	require.Nil(t, err)
	pemString, err := ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(t, err)

	creds, err = RegisterSystem(context.Background(), "Test Client Name", groupID, DefaultScope, pemString, []string{}, uuid.NewRandom().String())
	assert.Nil(t, err)
	assert.Equal(t, "Test Client Name", creds.ClientName)
	assert.NotNil(t, creds.ClientSecret)

	return
}

func CreateTestXDataV2(t *testing.T, db *gorm.DB) (creds Credentials, group Group) {
	groupID := RandomHexID()[0:4]

	group = Group{GroupID: groupID, XData: `{"group":"1"}`}
	err := db.Create(&group).Error
	require.Nil(t, err)

	_, pubKey, err := GenerateTestKeys(2048)
	require.Nil(t, err)
	pemString, err := ConvertPublicKeyToPEMString(&pubKey)
	require.Nil(t, err)

	s := SystemInput{
		ClientName: "Test Client Name",
		GroupID:    groupID,
		Scope:      DefaultScope,
		PublicKey:  pemString,
		IPs:        []string{"47.189.63.100"},
		TrackingID: uuid.NewRandom().String(),
		XData:      `{"impl": "2"}`,
	}
	creds, err = RegisterV2System(context.Background(), s)
	assert.Nil(t, err)
	assert.Equal(t, "Test Client Name", creds.ClientName)
	assert.NotNil(t, creds.ClientSecret)

	return
}

// GetLogger returns the underlying implementation of the field logger
func GetLogger(logger logrus.FieldLogger) *logrus.Logger {
	if entry, ok := logger.(*logrus.Entry); ok {
		return entry.Logger
	}
	// Must be a *logrus.Logger
	return logger.(*logrus.Logger)
}

package ssas

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type SystemsTestSuite struct {
	suite.Suite
	db *gorm.DB
}

func (s *SystemsTestSuite) SetupSuite() {
	s.db = GetGORMDbConnection()
}

func (s *SystemsTestSuite) TearDownSuite() {
	Close(s.db)
}

func (s *SystemsTestSuite) AfterTest() {
}

func (s *SystemsTestSuite) TestRevokeSystemKeyPair() {
	assert := s.Assert()

	group := Group{GroupID: "A00001"}
	s.db.Save(&group)
	system := System{GID: group.ID, ClientID: "test-revoke-system-key-pair-client"}

	err := system.RevokeSystemKeyPair()
	assert.NotNil(err)

	s.db.Save(&system)
	encryptionKey := EncryptionKey{SystemID: system.ID}
	s.db.Save(&encryptionKey)

	err = system.RevokeSystemKeyPair()
	assert.Nil(err)
	assert.Empty(system.EncryptionKeys)
	s.db.Unscoped().Find(&encryptionKey)
	assert.NotNil(encryptionKey.DeletedAt)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestGenerateSystemKeyPair() {
	assert := s.Assert()

	group := Group{GroupID: "abcdef123456"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := System{GID: group.ID}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	privateKeyStr, err := system.GenerateSystemKeyPair()
	assert.NoError(err)
	assert.NotEmpty(privateKeyStr)

	privKeyBlock, _ := pem.Decode([]byte(privateKeyStr))
	if privKeyBlock == nil || privKeyBlock.Bytes == nil {
		s.FailNow("unable to decode private key ", privateKeyStr)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		s.FailNow(err.Error())
	}

	var pubEncrKey EncryptionKey
	err = s.db.First(&pubEncrKey, "system_id = ?", system.ID).Error
	if err != nil {
		s.FailNow(err.Error())
	}
	pubKeyBlock, _ := pem.Decode([]byte(pubEncrKey.Body))
	publicKey, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		s.FailNow(err.Error())
	}
	assert.Equal(&privateKey.PublicKey, publicKey)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestGenerateSystemKeyPairAlreadyExists() {
	assert := s.Assert()

	group := Group{GroupID: "bcdefa234561"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := System{GID: group.ID}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	encrKey := EncryptionKey{
		SystemID: system.ID,
	}
	err = s.db.Create(&encrKey).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	privateKey, err := system.GenerateSystemKeyPair()
	systemIDStr := strconv.FormatUint(uint64(system.ID), 10)
	assert.EqualError(err, "encryption keypair already exists for system ID "+systemIDStr)
	assert.Empty(privateKey)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestGetEncryptionKey() {
	group := Group{GroupID: "test-get-encryption-key-group"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := System{GID: group.ID}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey := `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsZYpl2VjUja8VgkgoQ9K
lgjvcjwaQZ7pLGrIA/BQcm+KnCIYOHaDH15eVDKQ+M2qE4FHRwLec/DTqlwg8TkT
IYjBnXgN1Sg18y+SkSYYklO4cxlvMO3V8gaot9amPmt4YbpgG7CyZ+BOUHuoGBTh
z2v9wLlK4zPAs3pLln3R/4NnGFKw2Eku2JVFTotQ03gSmSzesZixicw8LxgYKbNV
oyTpERFansw6BbCJe7AP90rmaxCx80NiewFq+7ncqMbCMcqeUuCwk8MjS6bjvpcC
htFCqeRi6AAUDRg0pcG8yoM+jo13Z5RJPOIf3ofohncfH5wr5Q7qiOCE5VH4I7cp
OwIDAQAB
-----END RSA PUBLIC KEY-----`

	origKey := EncryptionKey{
		SystemID: system.ID,
		Body:     pubKey,
	}
	err = s.db.Create(&origKey).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	key, err := system.GetEncryptionKey("")
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), pubKey, key.Body)

	_ = CleanDatabase(group)
}

func (s *SystemsTestSuite) TestSystemSavePublicKey() {
	assert := s.Assert()

	clientID := uuid.NewRandom().String()
	groupID := "T33333"

	// Setup Group and System
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	assert.Nil(err)
	system := System{ClientID: clientID, GID: group.ID}
	err = s.db.Create(&system).Error
	assert.Nil(err)

	// Setup key
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err, "error creating random test keypair")
	publicKeyPKIX, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	assert.Nil(err, "unable to marshal public key")
	publicKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPKIX,
	})
	assert.NotNil(publicKeyBytes, "unexpectedly empty public key byte slice")

	// Save key
	err = system.SavePublicKey(bytes.NewReader(publicKeyBytes))
	if err != nil {
		assert.FailNow("error saving key: " + err.Error())
	}

	// Retrieve and verify
	storedKey, err := system.GetEncryptionKey("")
	assert.Nil(err)
	assert.NotNil(storedKey)
	assert.Equal(storedKey.Body, string(publicKeyBytes))

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestSystemSavePublicKeyInvalidKey() {
	assert := s.Assert()

	clientID := uuid.NewRandom().String()
	groupID := "T44444"

	// Setup Group and System
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	assert.Nil(err)
	system := System{ClientID: clientID, GID: group.ID}
	err = s.db.Create(&system).Error
	assert.Nil(err)

	emptyPEM := "-----BEGIN RSA PUBLIC KEY-----    -----END RSA PUBLIC KEY-----"
	invalidPEM :=
		`-----BEGIN RSA PUBLIC KEY-----
z2v9wLlK4zPAs3pLln3R/4NnGFKw2Eku2JVFTotQ03gSmSzesZixicw8LxgYKbNV
oyTpERFansw6BbCJe7AP90rmaxCx80NiewFq+7ncqMbCMcqeUuCwk8MjS6bjvpcC
htFCqeRi6AAUDRg0pcG8yoM+jo13Z5RJPOIf3ofohncfH5wr5Q7qiOCE5VH4I7cp
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsZYpl2VjUja8VgkgoQ9K
lgjvcjwaQZ7pLGrIA/BQcm+KnCIYOHaDH15eVDKQ+M2qE4FHRwLec/DTqlwg8TkT
IYjBnXgN1Sg18y+SkSYYklO4cxlvMO3V8gaot9amPmt4YbpgG7CyZ+BOUHuoGBTh
OwIDAQAB
-----END RSA PUBLIC KEY-----`
	keyPair, err := rsa.GenerateKey(rand.Reader, 512)
	assert.Nil(err, "unable to generate key pair")
	publicKeyPKIX, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	assert.Nil(err, "unable to marshal public key")
	lowBitPubKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPKIX,
	})
	assert.NotNil(lowBitPubKey, "unexpectedly empty public key byte slice")

	err = system.SavePublicKey(strings.NewReader(""))
	assert.NotNil(err, "empty string should not be saved")

	err = system.SavePublicKey(strings.NewReader(emptyPEM))
	assert.NotNil(err, "empty PEM should not be saved")

	err = system.SavePublicKey(strings.NewReader(invalidPEM))
	assert.NotNil(err, "invalid PEM should not be saved")

	err = system.SavePublicKey(bytes.NewReader(lowBitPubKey))
	assert.NotNil(err, "insecure public key should not be saved")

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestSystemPublicKeyEmpty() {
	assert := s.Assert()

	clientID := uuid.NewRandom().String()
	groupID := "T22222"

	// Setup Group and System
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	assert.Nil(err)
	system := System{ClientID: clientID, GID: group.ID}
	err = s.db.Create(&system).Error
	assert.Nil(err)

	emptyPEM := "-----BEGIN RSA PUBLIC KEY-----    -----END RSA PUBLIC KEY-----"
	validPEM, err := generatePublicKey(2048)
	assert.Nil(err)

	err = system.SavePublicKey(strings.NewReader(""))
	assert.EqualError(err, fmt.Sprintf("invalid public key for clientID %s: not able to decode PEM-formatted public key", clientID))
	k, err := system.GetEncryptionKey("")
	assert.EqualError(err, fmt.Sprintf("cannot find key for clientID %s: record not found", clientID))
	assert.Empty(k, "Empty string does not yield empty encryption key!")
	err = system.SavePublicKey(strings.NewReader(emptyPEM))
	assert.EqualError(err, fmt.Sprintf("invalid public key for clientID %s: not able to decode PEM-formatted public key", clientID))
	k, err = system.GetEncryptionKey("")
	assert.EqualError(err, fmt.Sprintf("cannot find key for clientID %s: record not found", clientID))
	assert.Empty(k, "Empty PEM key does not yield empty encryption key!")
	err = system.SavePublicKey(strings.NewReader(validPEM))
	assert.Nil(err)
	k, err = system.GetEncryptionKey("")
	assert.Nil(err)
	assert.NotEmpty(k, "Valid PEM key yields empty public key!")

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestEncryptionKeyModel() {
	assert := s.Assert()

	group := Group{GroupID: "A00000"}
	s.db.Save(&group)

	system := System{GID: group.ID}
	s.db.Save(&system)

	systemIDStr := strconv.FormatUint(uint64(system.ID), 10)
	encryptionKeyBytes := []byte(`{"body": "this is a public key", "system_id": ` + systemIDStr + `}`)
	encryptionKey := EncryptionKey{}
	err := json.Unmarshal(encryptionKeyBytes, &encryptionKey)
	assert.Nil(err)

	err = s.db.Save(&encryptionKey).Error
	assert.Nil(err)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestGetSystemByClientIDSuccess() {
	assert := s.Assert()

	group := Group{GroupID: "abcdef123456"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := System{GID: group.ID, ClientID: "987654zyxwvu", ClientName: "Client with System"}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	sys, err := GetSystemByClientID(system.ClientID)
	assert.Nil(err)
	assert.NotEmpty(sys)
	assert.Equal("Client with System", sys.ClientName)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestSystemClientGroupDuplicate() {
	assert := s.Assert()

	group1 := Group{GroupID: "fabcde612345"}
	err := s.db.Create(&group1).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	group2 := Group{GroupID: "efabcd561234"}
	err = s.db.Create(&group2).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := System{GID: group1.ID, ClientID: "498765uzyxwv", ClientName: "First Client"}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system = System{GID: group2.ID, ClientID: "498765uzyxwv", ClientName: "Duplicate Client"}
	err = s.db.Create(&system).Error
	assert.EqualError(err, "pq: duplicate key value violates unique constraint \"idx_client\"")

	sys, err := GetSystemByClientID(system.ClientID)
	assert.Nil(err)
	assert.NotEmpty(sys)
	assert.Equal("First Client", sys.ClientName)

	err = CleanDatabase(group1)
	assert.Nil(err)

	err = CleanDatabase(group2)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestRegisterSystemSuccess() {
	assert := s.Assert()

	trackingID := uuid.NewRandom().String()
	groupID := "T54321"
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey, err := generatePublicKey(2048)
	assert.Nil(err)

	creds, err := RegisterSystem("Create System Test", groupID, DefaultScope, pubKey, []string{}, trackingID)
	assert.Nil(err)
	assert.Equal("Create System Test", creds.ClientName)
	assert.NotEqual("", creds.ClientSecret)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestUpdateSystemSuccess() {
	assert := s.Assert()

	trackingID := uuid.NewRandom().String()
	groupID := "T54321"
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey, err := generatePublicKey(2048)
	assert.Nil(err)

	creds, err := RegisterSystem("Create System Test", groupID, DefaultScope, pubKey, []string{}, trackingID)
	assert.Nil(err)
	assert.Equal("Create System Test", creds.ClientName)
	assert.NotEqual("", creds.ClientSecret)

	var input = map[string]string{"client_name": "updated client name"}
	_, err = UpdateSystem(creds.SystemID, input)
	assert.Nil(err)
	sys, err := GetSystemByID(creds.SystemID)
	assert.Nil(err)
	assert.Equal("updated client name", sys.ClientName)

	input = map[string]string{"api_scope": "modified-scope"}
	_, err = UpdateSystem(creds.SystemID, input)
	assert.Nil(err)
	sys, err = GetSystemByID(creds.SystemID)
	assert.Nil(err)
	assert.Equal("modified-scope", sys.APIScope)

	input = map[string]string{"software_id": "modified-software-id"}
	_, err = UpdateSystem(creds.SystemID, input)
	assert.Nil(err)
	sys, err = GetSystemByID(creds.SystemID)
	assert.Nil(err)
	assert.Equal("modified-software-id", sys.SoftwareID)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestUpdateNonExistingSystem() {
	assert := s.Assert()

	var input = map[string]string{"client_name": "updated client name"}
	_, err := UpdateSystem("non-existing-system-id", input)
	assert.NotNil(err)
	assert.Equal("record not found for id=non-existing-system-id", err.Error())
}

func (s *SystemsTestSuite) TestRegisterSystemMissingData() {
	assert := s.Assert()

	trackingID := uuid.NewRandom().String()
	groupID := "T11223"
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey, err := generatePublicKey(2048)
	assert.Nil(err)

	// No clientName
	creds, err := RegisterSystem("", groupID, DefaultScope, pubKey, []string{}, trackingID)
	assert.EqualError(err, "clientName is required")
	assert.Empty(creds)

	// No scope = success
	creds, err = RegisterSystem("Register System Success2", groupID, "", pubKey, []string{}, trackingID)
	assert.Nil(err)
	assert.NotEmpty(creds)

	// No scope = success
	creds, err = RegisterSystem("Register System Failure", groupID, "badScope", pubKey, []string{}, trackingID)
	assert.NotNil(err)
	assert.Empty(creds)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestRegisterSystemIps() {
	assert := s.Assert()

	goodIps := []string{
		RandomIPv4(), // Single addresses are OK
		RandomIPv6(),
	}

	badIps := []string{
		"",
		"asdf",
		"256.0.0.1", // Invalid
		net.IPv4bcast.String(),
		net.IPv6loopback.String(),
		net.IPv4(8, 8, 8, 0).String() + "/24", // No ranges
	}

	trackingID := uuid.NewRandom().String()
	groupID := "T98987"
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey, err := generatePublicKey(2048)
	assert.Nil(err)

	for _, address := range goodIps {
		creds, err := RegisterSystem("Test system with "+address, groupID, DefaultScope, pubKey, []string{address}, trackingID)
		assert.Nil(err, fmt.Sprintf("%s should be a good IP, but was not allowed", address))
		assert.NotEmpty(creds, address+"should have been a valid IP")
		system, err := GetSystemByID(creds.SystemID)
		assert.Nil(err)
		ips, err := system.GetIPs()
		assert.Nil(err)
		assert.Equal([]string{address}, ips)
		ips, err = GetAllIPs()
		assert.Nil(err)
		assert.Contains(ips, address)
	}

	// We have no limit on the number of IP addresses that can be registered with a system
	creds, err := RegisterSystem("Test system with all good IPs", groupID, DefaultScope, pubKey, goodIps, trackingID)
	assert.Nil(err, "An array of good IP's should be a allowed, but was not")
	assert.NotEmpty(creds)

	for _, address := range badIps {
		creds, err = RegisterSystem("Test system with "+address, groupID, DefaultScope, pubKey, []string{address}, trackingID)
		if err == nil {
			assert.Fail(fmt.Sprintf("%s should be a bad IP, but was allowed; creds: %v", address, creds))
		} else {
			assert.EqualError(err, "error in ip address(es)")
		}
		assert.Empty(creds)
	}

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestRegisterSystemBadKey() {
	assert := s.Assert()

	trackingID := uuid.NewRandom().String()
	groupID := "T22334"
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey, err := generatePublicKey(1024)
	assert.Nil(err)

	// Blank key ok
	creds, err := RegisterSystem("Register System Failure", groupID, DefaultScope, "", []string{}, trackingID)
	assert.Nil(err, "error in public key")
	assert.NotEmpty(creds)

	// Invalid key not ok
	creds, err = RegisterSystem("Register System Failure", groupID, DefaultScope, "NotAKey", []string{}, trackingID)
	assert.EqualError(err, "error in public key")
	assert.Empty(creds)

	// Low key length not ok
	creds, err = RegisterSystem("Register System Failure", groupID, DefaultScope, pubKey, []string{}, trackingID)
	assert.EqualError(err, "error in public key")
	assert.Empty(creds)

	assert.Nil(CleanDatabase(group))
}

func generatePublicKey(bits int) (string, error) {
	return GeneratePublicKey(bits)
}

func (s *SystemsTestSuite) TestSaveSecret() {
	assert := s.Assert()

	group := Group{GroupID: "T21212"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := System{GID: group.ID, ClientID: "test-save-secret-client"}
	err = s.db.Create(&system).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	// First secret should save
	secret1, err := GenerateSecret()

	if err != nil {
		s.FailNow("cannot generate random secret")
	}
	hashedSecret1, err := NewHash(secret1)
	if err != nil {
		s.FailNow("cannot hash random secret")
	}
	err = system.SaveSecret(hashedSecret1.String())
	if err != nil {
		s.FailNow(err.Error())
	}

	// Second secret should cause first secret to be soft-deleted
	secret2, err := GenerateSecret()

	if err != nil {
		s.FailNow("cannot generate random secret")
	}
	hashedSecret2, err := NewHash(secret2)
	if err != nil {
		s.FailNow("cannot hash random secret")
	}
	err = system.SaveSecret(hashedSecret2.String())
	if err != nil {
		s.FailNow(err.Error())
	}

	// Verify we now retrieve second secret
	// Note that this also tests GetSecret()
	savedSecret, err := system.GetSecret()
	if err != nil {
		s.FailNow(err.Error())
	}
	assert.True(Hash(savedSecret.Hash).IsHashOf(secret2))

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestRevokeSecrets() {
	group := Group{GroupID: "test-deactivate-secrets-group"}
	s.db.Create(&group)
	system := System{GID: group.ID, ClientID: "test-deactivate-secrets-client"}
	s.db.Create(&system)
	secret := Secret{Hash: "test-deactivate-secrets-hash", SystemID: system.ID}
	s.db.Create(&secret)

	var systemSecrets []Secret
	s.db.Find(&systemSecrets, "system_id = ?", system.ID)
	assert.NotEmpty(s.T(), systemSecrets)

	err := system.RevokeSecret(fmt.Sprint(system.ID))
	assert.Nil(s.T(), err)
	s.db.Find(&systemSecrets, "system_id = ?", system.ID)
	assert.Empty(s.T(), systemSecrets)

	_ = CleanDatabase(group)
}

func (s *SystemsTestSuite) TestResetSecret() {
	group := Group{GroupID: "group-12345"}
	s.db.Create(&group)
	system := System{GID: group.ID, ClientID: "client-12345"}
	s.db.Create(&system)
	secret := Secret{Hash: "foo", SystemID: system.ID}
	s.db.Create(&secret)

	secret1 := Secret{}
	s.db.Where("system_id = ?", system.ID).First(&secret1)
	assert.Equal(s.T(), secret1.Hash, secret.Hash)

	credentials, err := system.ResetSecret("tracking-id")
	if err != nil {
		s.FailNow("Error from ResetSecret()", err.Error())
		return
	}

	assert.Nil(s.T(), err)
	assert.NotEmpty(s.T(), credentials)
	assert.NotEqual(s.T(), secret1.Hash, credentials.ClientSecret)

	_ = CleanDatabase(group)
}

func (s *SystemsTestSuite) TestScopeEnvSuccess() {
	key := "SSAS_DEFAULT_SYSTEM_SCOPE"
	newScope := "my_scope"
	oldScope := os.Getenv(key)
	err := os.Setenv(key, newScope)
	if err != nil {
		s.FailNow(err.Error())
	}
	getEnvVars()

	assert.Equal(s.T(), newScope, DefaultScope)
	err = os.Setenv(key, oldScope)
	assert.Nil(s.T(), err)
}

func (s *SystemsTestSuite) TestScopeEnvFailure() {
	scope := ""
	err := os.Setenv("SSAS_DEFAULT_SYSTEM_SCOPE", scope)
	if err != nil {
		s.FailNow(err.Error())
	}

	assert.Panics(s.T(), func() { getEnvVars() })
}

func makeTestSystem(db *gorm.DB) (Group, System, error) {
	groupID := "T" + RandomHexID()[:4]
	group := Group{GroupID: groupID}
	if err := db.Save(&group).Error; err != nil {
		return Group{}, System{}, err
	}
	system := System{GID: group.ID, GroupID: groupID, ClientID: "system-for-test-group-" + groupID}
	if err := db.Save(&system).Error; err != nil {
		return Group{}, System{}, err
	}
	return group, system, nil
}

func (s *SystemsTestSuite) TestGetSystemByIDWithKnownSystem() {
	g, system, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "unexpected error")
	require.Nil(s.T(), err, "unexpected error ", err)
	systemFromID, err := GetSystemByID(fmt.Sprint(system.ID))
	assert.Nil(s.T(), err, "unexpected error ", err)
	assert.Equal(s.T(), system.ID, systemFromID.ID)
	assert.Equal(s.T(), system.GID, systemFromID.GID)
	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSystemByIDWithNonExistentID() {
	// make sure there's at least one system
	g, _, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "can't make test system")
	var max uint
	row := s.db.Table("systems").Select("MAX(id)").Row()
	err = row.Scan(&max)
	assert.Nil(s.T(), err, "no max id?")
	_, err = GetSystemByID(fmt.Sprint(max + 1))
	require.NotEmpty(s.T(), err, "should not have found system for ID: ", max+1)
	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSystemByIDWithEmptyID() {
	_, err := GetSystemByID("")
	require.NotNil(s.T(), err, "found system for empty id")
}

func (s *SystemsTestSuite) TestGetSystemBySystemIDWithNonNumberID() {
	_, err := GetSystemByID("i am not a number")
	require.NotNil(s.T(), err, "found system for non-number id")
}

func (s *SystemsTestSuite) TestGetSystemByClientIDWithEmptyID() {
	_, err := GetSystemByClientID("")
	require.NotNil(s.T(), err, "found system for empty id")
}

func (s *SystemsTestSuite) TestGetSystemByClientIDWithNonNumberID() {
	_, err := GetSystemByClientID("i am not a number")
	require.NotNil(s.T(), err, "found system for non-number id")
}

func (s *SystemsTestSuite) TestGetSystemsByGroupIDWithZeroID() {
	systems, _ := GetSystemsByGroupID(0)
	assert.Empty(s.T(), systems, "found system for empty group id")
}

func (s *SystemsTestSuite) TestGetSystemsByGroupIDWithNonexistentID() {
	var badGroupID uint

	// make sure there's at least one system
	g, _, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "can't make test system")

	badGroupID = 99999
	systems, _ := GetSystemsByGroupID(badGroupID)
	assert.Empty(s.T(), systems, fmt.Sprintf("should not have found system for ID %d", badGroupID))
	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSystemsByGroupIDWithKnownSystem() {
	g, system, err := makeTestSystem(s.db)

	require.Nil(s.T(), err, "unexpected error ", err)
	systemsFromGroupID, err := GetSystemsByGroupID(g.ID)
	assert.Nil(s.T(), err, "unexpected error ", err)

	assert.Len(s.T(), systemsFromGroupID, 1, "should find exactly one system")

	// Don't stop the test (so we can run CleanDatabase() at the end), but also don't bother with the next two
	// assertions unless the previous one was true.
	if len(systemsFromGroupID) == 1 {
		assert.Equal(s.T(), system.ID, systemsFromGroupID[0].ID)
		assert.Equal(s.T(), system.GID, systemsFromGroupID[0].GID)
	}

	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestIsExpired() {
	groupID := "group-isExpiredTest"
	group := Group{GroupID: groupID}
	assert.Nil(s.T(), s.db.Create(&group).Error)
	system := System{GID: group.ID, GroupID: groupID, ClientID: "client-isExpiredTest"}
	assert.Nil(s.T(), s.db.Create(&system).Error)
	secret := Secret{Hash: "foo", SystemID: system.ID}
	assert.Nil(s.T(), s.db.Create(&secret).Error)

	// New secrets have not expired
	assert.False(s.T(), secret.IsExpired(), fmt.Sprintf("Why is this secret expired?  created_at=%v updated_at=%v", secret.CreatedAt, secret.UpdatedAt))

	// Old secrets have expired
	s.db.Exec("UPDATE secrets SET created_at = '2000-01-01', updated_at = '2000-01-01' WHERE system_id = ?", system.ID)
	err := s.db.First(&secret, secret.ID).Error
	assert.NoError(s.T(), err)
	assert.True(s.T(), secret.IsExpired())
	_ = CleanDatabase(group)
}

func (s *SystemsTestSuite) TestIPIsExpired() {
	address1 := RandomIPv4()
	address2 := RandomIPv4()
	groupID := "group-IPIsExpiredTest"
	group := Group{GroupID: groupID}
	assert.Nil(s.T(), s.db.Create(&group).Error)
	system := System{GID: group.ID, GroupID: groupID, ClientID: "client-IPIsExpiredTest"}
	assert.Nil(s.T(), s.db.Create(&system).Error)
	ip1 := IP{SystemID: system.ID, Address: address1}
	assert.Nil(s.T(), s.db.Create(&ip1).Error)
	ip2 := IP{SystemID: system.ID, Address: address2}
	assert.Nil(s.T(), s.db.Create(&ip2).Error)
	secret := Secret{Hash: "foo", SystemID: system.ID}
	assert.Nil(s.T(), s.db.Create(&secret).Error)

	// Addresses from an non-soft-deleted, unexpired system are returned
	allIps, err := GetAllIPs()
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), allIps, address1)
	assert.Contains(s.T(), allIps, address2)

	// Addresses from an expired system are not returned
	s.db.Exec("UPDATE secrets SET created_at = '2000-01-01', updated_at = '2000-01-01' WHERE system_id = ?", system.ID)
	err = s.db.First(&secret, secret.ID).Error
	assert.NoError(s.T(), err)
	allIps, err = GetAllIPs()
	assert.NoError(s.T(), err)
	assert.NotContains(s.T(), allIps, address1)
	assert.NotContains(s.T(), allIps, address2)

	// Addresses for revoked credentials are not returned
	s.db.Exec("UPDATE secrets SET created_at = now(), updated_at = now(), deleted_at = now() WHERE system_id = ?", system.ID)
	err = s.db.First(&secret, secret.ID).Error
	assert.Error(s.T(), err)
	allIps, err = GetAllIPs()
	assert.NoError(s.T(), err)
	assert.NotContains(s.T(), allIps, address1)
	assert.NotContains(s.T(), allIps, address2)

	// Addresses for soft-deleted systems are not returned
	s.db.Exec("UPDATE secrets SET deleted_at = null WHERE system_id = ?", system.ID)
	err = s.db.First(&secret, secret.ID).Error
	assert.NoError(s.T(), err)
	s.db.Exec("UPDATE systems SET deleted_at = now() WHERE id = ?", system.ID)
	err = s.db.First(&system, system.ID).Error
	assert.Error(s.T(), err)
	allIps, err = GetAllIPs()
	assert.NoError(s.T(), err)
	assert.NotContains(s.T(), allIps, address1)
	assert.NotContains(s.T(), allIps, address2)

	// Addresses for soft-deleted groups are not returned
	s.db.Exec("UPDATE systems SET deleted_at = null WHERE id = ?", system.ID)
	err = s.db.First(&system, system.ID).Error
	assert.NoError(s.T(), err)
	s.db.Exec("UPDATE groups SET deleted_at = now() WHERE id = ?", group.ID)
	err = s.db.First(&group, group.ID).Error
	assert.Error(s.T(), err)
	allIps, err = GetAllIPs()
	assert.NoError(s.T(), err)
	assert.NotContains(s.T(), allIps, address1)
	assert.NotContains(s.T(), allIps, address2)

	// Addresses for soft-deleted ips are not returned
	s.db.Exec("UPDATE systems SET deleted_at = null WHERE id = ?", system.ID)
	err = s.db.First(&system, system.ID).Error
	assert.NoError(s.T(), err)
	s.db.Exec("UPDATE groups SET deleted_at = now() WHERE id = ?", group.ID)
	err = s.db.First(&group, group.ID).Error
	assert.Error(s.T(), err)
	allIps, err = GetAllIPs()
	assert.NoError(s.T(), err)
	assert.NotContains(s.T(), allIps, address1)
	assert.NotContains(s.T(), allIps, address2)

	_ = CleanDatabase(group)
}

func TestSystemsTestSuite(t *testing.T) {
	suite.Run(t, new(SystemsTestSuite))
}

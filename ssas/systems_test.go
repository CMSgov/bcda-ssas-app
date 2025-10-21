package ssas

import (
	"bytes"
	"context"
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

	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type SystemsTestSuite struct {
	suite.Suite
	db       *gorm.DB
	logEntry *APILoggerEntry
	r        *SystemRepository
}

func (s *SystemsTestSuite) SetupSuite() {
	SetupLogger()
	cfg.LoadEnvConfigs()
	s.logEntry = MakeTestStructuredLoggerEntry(logrus.Fields{"cms_id": "A9999", "request_id": uuid.NewUUID().String()})
}

func (s *SystemsTestSuite) SetupTest() {
	var err error
	s.db, err = CreateDB()
	require.NoError(s.T(), err)
	s.r = NewSystemRepository(s.db)
}

func (s *SystemsTestSuite) TearDownTest() {
	db, err := s.db.DB()
	require.NoError(s.T(), err)
	err = db.Close()
	require.NoError(s.T(), err)
}

func TestSystemsTestSuite(t *testing.T) {
	suite.Run(t, new(SystemsTestSuite))
}

func (s *SystemsTestSuite) TestGetEncryptionKey() {
	sys, group, pubKey, _ := s.createSystemWithPubKey()

	key, err := s.r.GetEncryptionKey(context.Background(), sys)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), pubKey, key.Body)

	_ = CleanDatabase(group)
}

func (s *SystemsTestSuite) TestFindEncryptionKey() {
	assert := s.Assert()
	sys, group, pubKey, pubKeyId := s.createSystemWithPubKey()

	key, err := s.r.FindEncryptionKey(context.Background(), sys, "", pubKeyId)
	assert.Nil(err)
	assert.Equal(pubKey, key.Body)
	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestFindEncryptionKeyNotFound() {
	assert := s.Assert()
	sys, group, _, _ := s.createSystemWithPubKey()

	_, err := s.r.FindEncryptionKey(context.Background(), sys, "", uuid.NewRandom().String())
	assert.NotNil(err)
	assert.Contains(err.Error(), "cannot find key for systemId")

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestFindEncryptionKeyForAnotherSystem() {
	assert := s.Assert()
	sys1, group1, _, _ := s.createSystemWithPubKey()
	_, group2, _, kid2 := s.createSystemWithPubKey()

	_, err := s.r.FindEncryptionKey(context.Background(), sys1, "", kid2)

	assert.NotNil(err)
	assert.Contains(err.Error(), "cannot find key for systemId")

	err = CleanDatabase(group1)
	assert.Nil(err)
	err = CleanDatabase(group2)
	assert.Nil(err)
}

func (s *SystemsTestSuite) createSystemWithPubKey() (System, Group, string, string) {
	group := Group{GroupID: uuid.New()}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	system := System{
		GID:      group.ID,
		ClientID: uuid.New(),
	}
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
		UUID:     uuid.NewRandom().String(),
	}
	err = s.db.Create(&origKey).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	return system, group, pubKey, origKey.UUID

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
	storedKey, err := s.r.SavePublicKey(s.db, system, bytes.NewReader(publicKeyBytes), "", true)
	if err != nil {
		assert.FailNow("error saving key: " + err.Error())
	}

	// Retrieve and verify
	assert.Nil(err)
	assert.NotNil(storedKey)
	assert.Equal(storedKey.Body, string(publicKeyBytes))

	keyPair, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKeyPKIX, _ = x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	publicKeyBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPKIX,
	})
	_, _ = s.r.SavePublicKey(s.db, system, bytes.NewReader(publicKeyBytes), "", true)
	keys, _ := s.r.GetEncryptionKeys(context.Background(), system)
	assert.Len(keys, 1)

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
	keyPair, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec
	assert.Nil(err, "unable to generate key pair")
	publicKeyPKIX, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	assert.Nil(err, "unable to marshal public key")
	lowBitPubKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyPKIX,
	})
	assert.NotNil(lowBitPubKey, "unexpectedly empty public key byte slice")

	_, err = s.r.SavePublicKey(s.db, system, strings.NewReader(""), "", true)
	assert.NotNil(err, "empty string should not be saved")

	_, err = s.r.SavePublicKey(s.db, system, strings.NewReader(emptyPEM), "", true)
	assert.NotNil(err, "empty PEM should not be saved")

	_, err = s.r.SavePublicKey(s.db, system, strings.NewReader(invalidPEM), "", true)
	assert.NotNil(err, "invalid PEM should not be saved")

	_, err = s.r.SavePublicKey(s.db, system, bytes.NewReader(lowBitPubKey), "", true)
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
	validPEM, _, _, err := generatePublicKey(2048)
	assert.Nil(err)

	_, err = s.r.SavePublicKey(s.db, system, strings.NewReader(""), "", true)
	assert.EqualError(err, fmt.Sprintf("invalid public key for clientID %s: not able to decode PEM-formatted public key", clientID))

	k, err := s.r.GetEncryptionKey(context.Background(), system)
	assert.EqualError(err, fmt.Sprintf("cannot find key for clientID %s: record not found", clientID))
	assert.Empty(k, "Empty string does not yield empty encryption key!")

	_, err = s.r.SavePublicKey(s.db, system, strings.NewReader(emptyPEM), "", true)
	assert.EqualError(err, fmt.Sprintf("invalid public key for clientID %s: not able to decode PEM-formatted public key", clientID))

	k, err = s.r.GetEncryptionKey(context.Background(), system)
	assert.EqualError(err, fmt.Sprintf("cannot find key for clientID %s: record not found", clientID))
	assert.Empty(k, "Empty PEM key does not yield empty encryption key!")

	_, err = s.r.SavePublicKey(s.db, system, strings.NewReader(validPEM), "", true)
	assert.Nil(err)

	k, err = s.r.GetEncryptionKey(context.Background(), system)
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

	sys, err := s.r.GetSystemByClientID(context.Background(), system.ClientID)
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
	assert.EqualError(err, "ERROR: duplicate key value violates unique constraint \"idx_client\" (SQLSTATE 23505)")

	sys, err := s.r.GetSystemByClientID(context.Background(), system.ClientID)
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

	pubKey, _, _, err := generatePublicKey(2048)
	assert.Nil(err)

	creds, err := s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Create System Test", groupID, cfg.DefaultScope, pubKey, []string{}, trackingID)
	assert.Nil(err)
	assert.Equal("Create System Test", creds.ClientName)
	assert.NotEqual("", creds.ClientSecret)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestRegisterSystem_SetsSGAKey() {
	assert := s.Assert()

	ctx := context.Background()
	ctx = context.WithValue(ctx, constants.CtxSGAKey, "test-sga")

	trackingID := uuid.NewRandom().String()
	groupID := "T54321"
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey, _, _, err := generatePublicKey(2048)
	assert.Nil(err)

	creds, err := s.r.RegisterSystem(context.WithValue(ctx, CtxLoggerKey, s.logEntry), "Create System Test", groupID, cfg.DefaultScope, pubKey, []string{}, trackingID)
	assert.Nil(err)

	gotSystem, err := s.r.GetSystemByID(ctx, creds.SystemID)
	assert.Nil(err)
	assert.Equal("test-sga", gotSystem.SGAKey)

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

	pubKey, _, _, err := generatePublicKey(2048)
	assert.Nil(err)

	creds, err := s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Create System Test", groupID, cfg.DefaultScope, pubKey, []string{}, trackingID)
	assert.Nil(err)
	assert.Equal("Create System Test", creds.ClientName)
	assert.NotEqual("", creds.ClientSecret)

	var input = map[string]string{"client_name": "updated client name"}
	_, err = s.r.UpdateSystem(context.Background(), creds.SystemID, input)
	assert.Nil(err)
	sys, err := s.r.GetSystemByID(context.Background(), creds.SystemID)
	assert.Nil(err)
	assert.Equal("updated client name", sys.ClientName)

	input = map[string]string{"api_scope": "modified-scope"}
	_, err = s.r.UpdateSystem(context.Background(), creds.SystemID, input)
	assert.Nil(err)
	sys, err = s.r.GetSystemByID(context.Background(), creds.SystemID)
	assert.Nil(err)
	assert.Equal("modified-scope", sys.APIScope)

	input = map[string]string{"software_id": "modified-software-id"}
	_, err = s.r.UpdateSystem(context.Background(), creds.SystemID, input)
	assert.Nil(err)
	sys, err = s.r.GetSystemByID(context.Background(), creds.SystemID)
	assert.Nil(err)
	assert.Equal("modified-software-id", sys.SoftwareID)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestUpdateNonExistingSystem() {
	assert := s.Assert()

	var input = map[string]string{"client_name": "updated client name"}
	_, err := s.r.UpdateSystem(context.Background(), "non-existing-system-id", input)
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

	pubKey, _, _, err := generatePublicKey(2048)
	assert.Nil(err)

	// No clientName
	creds, err := s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "", groupID, cfg.DefaultScope, pubKey, []string{}, trackingID)
	assert.EqualError(err, "clientName is required")
	assert.Empty(creds)

	// No scope = success
	creds, err = s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Register System Success2", groupID, "", pubKey, []string{}, trackingID)
	assert.Nil(err)
	assert.NotEmpty(creds)

	// No scope = success
	creds, err = s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Register System Failure", groupID, "badScope", pubKey, []string{}, trackingID)
	assert.NotNil(err)
	assert.Empty(creds)

	err = CleanDatabase(group)
	assert.Nil(err)
}

func (s *SystemsTestSuite) TestRegisterSystemIps() {
	assert := s.Assert()

	type test struct {
		ip     string
		valid  bool
		err    error
		errmsg string
	}

	tests := []test{
		{RandomIPv4(), true, nil, ""},
		{RandomIPv6(), true, nil, ""},
		{"", false, nil, ""},
		{"asdf", false, nil, ""},
		{"256.0.0.1", false, nil, ""},
		{net.IPv4bcast.String(), false, nil, ""},
		{net.IPv6loopback.String(), false, nil, ""},
		{net.IPv4(8, 8, 8, 0).String() + "/24", false, nil, ""},
	}

	goodIps := []string{
		RandomIPv4(), // Single addresses are OK
		RandomIPv6(),
	}

	trackingID := uuid.NewRandom().String()
	groupID := "T98987"
	group := Group{GroupID: groupID}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	pubKey, _, _, err := generatePublicKey(2048)
	assert.Nil(err)

	for _, tc := range tests {
		if tc.valid {
			creds, err := s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Test system with "+tc.ip, groupID, cfg.DefaultScope, pubKey, []string{tc.ip}, trackingID)
			assert.Nil(err, fmt.Sprintf("%s should be a good IP, but was not allowed", tc.ip))
			assert.NotEmpty(creds, tc.ip+"should have been a valid IP")
			system, err := s.r.GetSystemByID(context.Background(), creds.SystemID)
			assert.Nil(err)
			ips, err := s.r.GetIPs(system)
			assert.Nil(err)
			assert.Equal([]string{tc.ip}, ips)
			ips, err = GetAllIPs(s.db)
			assert.Nil(err)
			assert.Contains(ips, tc.ip)
		} else {
			creds, err := s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Test system with "+tc.ip, groupID, cfg.DefaultScope, pubKey, []string{tc.ip}, trackingID)
			if err == nil {
				assert.Fail(fmt.Sprintf("%s should be a bad IP, but was allowed; creds: %v", tc.ip, creds))
			} else {
				assert.ErrorContains(err, "invalid IP ")
			}
			assert.Empty(creds)

		}

	}

	//We have no limit on the number of IP addresses that can be registered with a system
	creds, err := s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Test system with all good IPs", groupID, cfg.DefaultScope, pubKey, goodIps, trackingID)
	assert.Nil(err, "An array of good IP's should be a allowed, but was not")
	assert.NotEmpty(creds)

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

	pubKey, _, _, err := generatePublicKey(1024)
	assert.Nil(err)

	type test struct {
		key   string
		empty bool
		err   bool
	}

	tests := []test{
		{"", false, false},
		{"notakey", true, true},
		{pubKey, true, true},
	}

	for _, tc := range tests {
		creds, err := s.r.RegisterSystem(context.WithValue(context.Background(), CtxLoggerKey, s.logEntry), "Register System Failure", groupID, cfg.DefaultScope, tc.key, []string{}, trackingID)
		if tc.empty {
			assert.Empty(creds)
		} else {
			assert.NotEmpty(creds)
		}
		if tc.err {
			assert.ErrorContains(err, "invalid public key for clientID")
		} else {
			assert.Nil(err)
		}

	}

	assert.Nil(CleanDatabase(group))
}

func generatePublicKey(bits int) (string, string, *rsa.PrivateKey, error) {
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
	err = s.r.SaveSecret(context.Background(), system, hashedSecret1.String())
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
	err = s.r.SaveSecret(context.Background(), system, hashedSecret2.String())
	if err != nil {
		s.FailNow(err.Error())
	}

	// Verify we now retrieve second secret
	// Note that this also tests GetSecret()
	savedSecret, err := s.r.GetSecret(context.Background(), system)
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

	err := s.r.RevokeSecret(context.Background(), system)
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

	credentials, err := s.r.ResetSecret(context.Background(), system)
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
	cfg.LoadEnvConfigs()

	assert.Equal(s.T(), newScope, cfg.DefaultScope)
	err = os.Setenv(key, oldScope)
	assert.Nil(s.T(), err)
}

func (s *SystemsTestSuite) TestEmptyGoPath() {
	err := os.Setenv("GOPATH", "")
	if err != nil {
		s.FailNow(err.Error())
	}
	cfg.LoadEnvConfigs()
	assert.Equal(s.T(), "bcda-api", cfg.DefaultScope)
}

func (s *SystemsTestSuite) TestScopeEnvDebug() {
	cfg.LoadEnvConfigs()
	assert.Equal(s.T(), "bcda-api", cfg.DefaultScope)
}

func (s *SystemsTestSuite) TestScopeEnvFailure() {
	scope := ""
	err := os.Setenv("SSAS_DEFAULT_SYSTEM_SCOPE", scope)
	if err != nil {
		s.FailNow(err.Error())
	}

	assert.Panics(s.T(), func() { cfg.LoadEnvConfigs() })
}

func makeTestSystem(db *gorm.DB) (Group, System, error) {
	groupID := "T" + RandomHexID()[:4]
	group := Group{GroupID: groupID}
	if err := db.Save(&group).Error; err != nil {
		return Group{}, System{}, err
	}
	system := System{GID: group.ID, GroupID: groupID, ClientID: "system-for-test-group-" + groupID, SGAKey: "test-sga"}
	if err := db.Save(&system).Error; err != nil {
		return Group{}, System{}, err
	}
	return group, system, nil
}

func (s *SystemsTestSuite) TestGetSystemByIDWithKnownSystem() {
	g, system, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "unexpected error")
	require.Nil(s.T(), err, "unexpected error ", err)
	systemFromID, err := s.r.GetSystemByID(context.Background(), fmt.Sprint(system.ID))
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
	_, err = s.r.GetSystemByID(context.Background(), fmt.Sprint(max+1))
	require.NotEmpty(s.T(), err, "should not have found system for ID: ", max+1)
	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSystemByIDWithEmptyID() {
	_, err := s.r.GetSystemByID(context.Background(), "")
	require.NotNil(s.T(), err, "found system for empty id")
}

func (s *SystemsTestSuite) TestGetSystemByIDWithNonNumberID() {
	_, err := s.r.GetSystemByID(context.Background(), "i am not a number")
	require.NotNil(s.T(), err, "found system for non-number id")
}

func (s *SystemsTestSuite) TestGetSystemByClientIDWithEmptyID() {
	_, err := s.r.GetSystemByClientID(context.Background(), "")
	require.NotNil(s.T(), err, "found system for empty id")
}

func (s *SystemsTestSuite) TestGetSystemByClientIDWithNonNumberID() {
	_, err := s.r.GetSystemByClientID(context.Background(), "i am not a number")
	require.NotNil(s.T(), err, "found system for non-number id")
}

func (s *SystemsTestSuite) TestGetSystemByID_WithSGA_Success() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, constants.CtxSGAKey, "test-sga")

	g, expSystem, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "unexpected error")
	require.Nil(s.T(), err, "unexpected error ", err)

	gotSystem, err := s.r.GetSystemByID(ctx, fmt.Sprint(expSystem.ID))
	assert.Nil(s.T(), err, "unexpected error ", err)
	assert.Equal(s.T(), expSystem.ID, gotSystem.ID)
	assert.Equal(s.T(), expSystem.GID, gotSystem.GID)
	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSystemByID_WithSGA_UnauthorizedRequester() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, constants.CtxSGAKey, "different-sga")

	g, expSystem, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "unexpected error")
	require.Nil(s.T(), err, "unexpected error ", err)

	gotSystem, err := s.r.GetSystemByID(ctx, fmt.Sprint(expSystem.ID))
	assert.ErrorContains(s.T(), err, "requesting SGA does not have access to this system, id:")
	assert.Equal(s.T(), System{}.ID, gotSystem.ID)

	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSystemByClientID_WithSGA_Success() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, constants.CtxSGAKey, "test-sga")

	group := Group{GroupID: "abcdef123456"}
	err := s.db.Create(&group).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	expSystem := System{GID: group.ID, ClientID: "987654zyxwvu", ClientName: "Client with System", SGAKey: "test-sga"} //gitleaks:allow
	err = s.db.Create(&expSystem).Error
	if err != nil {
		s.FailNow(err.Error())
	}

	gotSystem, err := s.r.GetSystemByClientID(ctx, fmt.Sprint(expSystem.ClientID))
	assert.Nil(s.T(), err, "unexpected error ", err)
	assert.Equal(s.T(), expSystem.ID, gotSystem.ID)
	assert.Equal(s.T(), expSystem.GID, gotSystem.GID)

	_ = CleanDatabase(group)
}

func (s *SystemsTestSuite) TestGetSystemsByGroupIDString_WithSGA_Success() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, constants.CtxSGAKey, "test-sga")

	g, expSystem, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "unexpected error")
	require.Nil(s.T(), err, "unexpected error ", err)

	gotSystems, err := GetSystemsByGroupIDString(ctx, fmt.Sprint(g.GroupID))
	assert.Nil(s.T(), err, "unexpected error ", err)
	assert.Equal(s.T(), expSystem.ID, gotSystems[0].ID)
	assert.Equal(s.T(), expSystem.GID, gotSystems[0].GID)

	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSGAKeyByGroupID() {
	g, expSystem, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "unexpected error")
	require.Nil(s.T(), err, "unexpected error ", err)

	sgaKey, err := GetSGAKeyByGroupID(context.Background(), s.db, fmt.Sprint(g.GroupID))
	assert.Nil(s.T(), err, "unexpected error ", err)
	assert.Equal(s.T(), expSystem.SGAKey, sgaKey)

	_ = CleanDatabase(g)
}

func (s *SystemsTestSuite) TestGetSGAKeyByGroupID_BadGroupID() {
	g, _, err := makeTestSystem(s.db)
	assert.Nil(s.T(), err, "unexpected error")
	require.Nil(s.T(), err, "unexpected error ", err)

	sgaKey, err := GetSGAKeyByGroupID(context.Background(), s.db, "different-group-id")
	assert.Equal(s.T(), "", sgaKey)
	assert.Nil(s.T(), err)

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
	allIps, err := GetAllIPs(s.db)
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), allIps, address1)
	assert.Contains(s.T(), allIps, address2)

	// Addresses from an expired system are not returned
	s.db.Exec("UPDATE secrets SET created_at = '2000-01-01', updated_at = '2000-01-01' WHERE system_id = ?", system.ID)
	err = s.db.First(&secret, secret.ID).Error
	assert.NoError(s.T(), err)
	allIps, err = GetAllIPs(s.db)
	assert.NoError(s.T(), err)
	assert.NotContains(s.T(), allIps, address1)
	assert.NotContains(s.T(), allIps, address2)

	// Addresses for revoked credentials are not returned
	s.db.Exec("UPDATE secrets SET created_at = now(), updated_at = now(), deleted_at = now() WHERE system_id = ?", system.ID)
	err = s.db.First(&secret, secret.ID).Error
	assert.Error(s.T(), err)
	allIps, err = GetAllIPs(s.db)
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
	allIps, err = GetAllIPs(s.db)
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
	allIps, err = GetAllIPs(s.db)
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
	allIps, err = GetAllIPs(s.db)
	assert.NoError(s.T(), err)
	assert.NotContains(s.T(), allIps, address1)
	assert.NotContains(s.T(), allIps, address2)

	_ = CleanDatabase(group)
}

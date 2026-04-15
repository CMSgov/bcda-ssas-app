package ssas

import (
	"context"
	"io"
	"time"

	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

type SystemRepositoryMock struct {
	mock.Mock
}

func (m *SystemRepositoryMock) SaveClientToken(ctx context.Context, system System, label string, groupXData string, expiration time.Time) (*ClientToken, string, error) {
	args := m.Called(ctx, system, label, groupXData, expiration)
	return args.Get(0).(*ClientToken), args.String(1), args.Error(2)
}

func (m *SystemRepositoryMock) GetClientTokens(ctx context.Context, system System) ([]ClientToken, error) {
	args := m.Called(ctx, system)
	return args.Get(0).([]ClientToken), args.Error(1)
}

func (m *SystemRepositoryMock) DeleteClientToken(ctx context.Context, system System, tokenID string) error {
	args := m.Called(ctx, system, tokenID)
	return args.Error(0)
}

func (m *SystemRepositoryMock) SaveSecret(ctx context.Context, system System, hashedSecret string) error {
	args := m.Called(ctx, system, hashedSecret)
	return args.Error(0)
}

func (m *SystemRepositoryMock) GetSecret(ctx context.Context, system System) (Secret, error) {
	args := m.Called(ctx, system)
	return args.Get(0).(Secret), args.Error(1)
}

func (m *SystemRepositoryMock) SaveTokenTime(ctx context.Context, system System) (err error) {
	args := m.Called(ctx, system)
	return args.Error(0)
}

func (m *SystemRepositoryMock) RevokeSecret(ctx context.Context, system System) error {
	args := m.Called(ctx, system)
	return args.Error(0)
}

func (m *SystemRepositoryMock) deactivateSecrets(ctx context.Context, system System) error {
	args := m.Called(ctx, system)
	return args.Error(0)
}

func (m *SystemRepositoryMock) GetEncryptionKeys(ctx context.Context, system System) ([]EncryptionKey, error) {
	args := m.Called(ctx, system)
	return args.Get(0).([]EncryptionKey), args.Error(1)
}

func (m *SystemRepositoryMock) DeleteEncryptionKey(ctx context.Context, system System, keyID string) error {
	args := m.Called(ctx, system, keyID)
	return args.Error(0)
}

func (m *SystemRepositoryMock) SavePublicKey(tx *gorm.DB, system System, publicKey io.Reader, signature string, onlyOne bool) (*EncryptionKey, error) {
	args := m.Called(system)
	return args.Get(0).(*EncryptionKey), args.Error(1)
}

func (m *SystemRepositoryMock) DeleteIP(ctx context.Context, system System, ipID string) error {
	args := m.Called(ctx, system, ipID)
	return args.Error(0)
}

func (m *SystemRepositoryMock) GetIPs(system System) ([]string, error) {
	args := m.Called(system)
	return args.Get(0).([]string), args.Error(1)
}

func (m *SystemRepositoryMock) GetIPsData(ctx context.Context, system System) ([]IP, error) {
	args := m.Called(ctx, system)
	return args.Get(0).([]IP), args.Error(1)
}

func (m *SystemRepositoryMock) ResetSecret(ctx context.Context, system System) (Credentials, error) {
	args := m.Called(ctx, system)
	return args.Get(0).(Credentials), args.Error(1)
}

func (m *SystemRepositoryMock) RegisterIP(ctx context.Context, system System, address string) (IP, error) {
	args := m.Called(ctx, system, address)
	return args.Get(0).(IP), args.Error(1)
}

func (m *SystemRepositoryMock) GetIps(ctx context.Context, system System) ([]IP, error) {
	args := m.Called(ctx, system)
	return args.Get(0).([]IP), args.Error(1)
}

func (m *SystemRepositoryMock) FindEncryptionKey(ctx context.Context, system System, trackingID string, keyId string) (EncryptionKey, error) {
	args := m.Called(ctx, system, trackingID, keyId)
	return args.Get(0).(EncryptionKey), args.Error(1)
}

func (m *SystemRepositoryMock) GetEncryptionKey(ctx context.Context, system System) (EncryptionKey, error) {
	args := m.Called(ctx, system)
	return args.Get(0).(EncryptionKey), args.Error(1)
}

func (m *SystemRepositoryMock) GetSystemByID(ctx context.Context, id string) (System, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(System), args.Error(1)
}

func (m *SystemRepositoryMock) RegisterV2System(ctx context.Context, input SystemInput) (Credentials, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(Credentials), args.Error(1)
}

func (m *SystemRepositoryMock) RegisterSystem(ctx context.Context, clientName string, groupID string, scope string, publicKeyPEM string, ips []string, trackingID string) (Credentials, error) {
	args := m.Called(ctx, clientName, groupID, scope, publicKeyPEM, ips, trackingID)
	return args.Get(0).(Credentials), args.Error(1)
}

func (m *SystemRepositoryMock) registerSystem(ctx context.Context, input SystemInput, isV2 bool) (Credentials, error) {
	args := m.Called(ctx, input, isV2)
	return args.Get(0).(Credentials), args.Error(1)
}

func (m *SystemRepositoryMock) UpdateSystem(ctx context.Context, id string, v map[string]string) (System, error) {
	args := m.Called(ctx, id, v)
	return args.Get(0).(System), args.Error(1)
}

func (m *SystemRepositoryMock) GetSystemByClientID(ctx context.Context, clientID string) (System, error) {
	args := m.Called(ctx, clientID)
	return args.Get(0).(System), args.Error(1)
}

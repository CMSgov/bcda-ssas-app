package cfg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEnvConfigsEmptyEnv(t *testing.T) {
	origEnv := os.Getenv("DEPLOYMENT_TARGET")
	t.Cleanup(func() {
		err := os.Setenv("DEPLOYMENT_TARGET", origEnv)
		require.NoError(t, err)
	})
	err := os.Setenv("DEPLOYMENT_TARGET", "")
	require.NoError(t, err)
	assert.NotPanics(t, func() {
		LoadEnvConfigs()
	}, "LoadEnvConfigs should not have panicked")

}

func TestLoadEnvConfigsNoFileForEnvName(t *testing.T) {
	origEnv := os.Getenv("DEPLOYMENT_TARGET")
	t.Cleanup(func() {
		err := os.Setenv("DEPLOYMENT_TARGET", origEnv)
		require.NoError(t, err)
	})
	err := os.Setenv("DEPLOYMENT_TARGET", "foo")
	require.NoError(t, err)
	assert.Panics(t, func() {
		LoadEnvConfigs()
	}, "LoadEnvConfigs should have panicked")
}

func TestLoadEnvConfigsDebug(t *testing.T) {
	origEnv := os.Getenv("DEPLOYMENT_TARGET")
	t.Cleanup(func() {
		err := os.Setenv("DEPLOYMENT_TARGET", origEnv)
		require.NoError(t, err)
	})
	err := os.Setenv("DEBUG", "true")
	require.NoError(t, err)
	assert.NotPanics(t, func() {
		LoadEnvConfigs()
	}, "LoadEnvConfigs should not have panicked")
	iter := os.Getenv("SSAS_HASH_ITERATIONS")
	key := os.Getenv("SSAS_HASH_KEY_LENGTH")
	salt := os.Getenv("SSAS_HASH_SALT_SIZE")
	assert.Equal(t, "130000", iter)
	assert.Equal(t, "64", key)
	assert.Equal(t, "32", salt)
}

func TestLoadEnvConfigsHashDefaults(t *testing.T) {
	origEnv := os.Getenv("DEPLOYMENT_TARGET")
	origHashIter := os.Getenv("SSAS_HASH_ITERATIONS")
	origHashKeyLen := os.Getenv("SSAS_HASH_KEY_LENGTH")
	origSaltSize := os.Getenv("SSAS_HASH_SALT_SIZE")
	t.Cleanup(func() {
		err := os.Setenv("DEPLOYMENT_TARGET", origEnv)
		require.NoError(t, err)
		err = os.Setenv("SSAS_HASH_ITERATIONS", origHashIter)
		require.NoError(t, err)
		err = os.Setenv("SSAS_HASH_KEY_LENGTH", origHashKeyLen)
		require.NoError(t, err)
		err = os.Setenv("SSAS_HASH_SALT_SIZE", origSaltSize)
		require.NoError(t, err)
	})
	err := os.Setenv("SSAS_HASH_ITERATIONS", "0")
	require.NoError(t, err)
	err = os.Setenv("SSAS_HASH_KEY_LENGTH", "origHashKeyLen")
	require.NoError(t, err)
	err = os.Setenv("SSAS_HASH_SALT_SIZE", "20")
	require.NoError(t, err)
	assert.Panics(t, func() {
		LoadEnvConfigs()
	}, "LoadEnvConfigs should have panicked")
}

func TestLoadEnvConfigsHashSet(t *testing.T) {
	origEnv := os.Getenv("DEPLOYMENT_TARGET")
	t.Cleanup(func() {
		err := os.Setenv("DEPLOYMENT_TARGET", origEnv)
		require.NoError(t, err)
	})
	err := os.Setenv("SSAS_HASH_ITERATIONS", "1")
	require.NoError(t, err)
	err = os.Setenv("SSAS_HASH_KEY_LENGTH", "1")
	require.NoError(t, err)
	err = os.Setenv("SSAS_HASH_SALT_SIZE", "1")
	require.NoError(t, err)
	assert.NotPanics(t, func() {
		LoadEnvConfigs()
	}, "LoadEnvConfigs should not have panicked")
}

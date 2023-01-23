package public

import (
	"testing"
)

// SetMockTokenCreator sets the current token creator to the one that's supplied in this function.
// It leverages the Cleanup() func to ensure the original token creator is restored at the end of the test.
func SetMockAccessTokenCreator(t *testing.T, other *MockTokenCreator) {
	// Ensure that we restore the original token creator when the test completes
	originalAccessTokenCreator := accessTokenCreator
	t.Cleanup(func() {
		accessTokenCreator = originalAccessTokenCreator
	})
	accessTokenCreator = other
}

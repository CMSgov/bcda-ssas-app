package public

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/CMSgov/bcda-ssas-app/ssas/service"
)

type PublicTokenTestSuite struct {
	suite.Suite
	server *service.Server
}

func (s *PublicTokenTestSuite) SetupSuite() {
	info := make(map[string][]string)
	info["public"] = []string{"token", "register"}
	s.server = Server()
	err := os.Setenv("DEBUG", "true")
	assert.Nil(s.T(), err)
}

func (s *PublicTokenTestSuite) TestMintRegistrationToken() {
	groupIDs := []string{"A0000", "A0001"}
	token, ts, err := MintRegistrationToken("my_okta_id", groupIDs)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), token)
	assert.NotNil(s.T(), ts)
}

func (s *PublicTokenTestSuite) TestMintRegistrationTokenMissingID() {
	groupIDs := []string{"", ""}
	token, ts, err := MintRegistrationToken("my_okta_id", groupIDs)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), token)
	assert.Equal(s.T(), "", ts)
}

func (s *PublicTokenTestSuite) TestMintAccessToken() {
	data := `"{\"cms_ids\":[\"T67890\",\"T54321\"]}"`
	commonClaims := CreateCommonClaims("AccessToken", "", "2", service.TestGroupID, data, "", nil)

	accessTokenGenerator := AccessTokenCreator{}
	t, ts, err := accessTokenGenerator.GenerateToken(commonClaims)

	require.Nil(s.T(), err)
	assert.NotEmpty(s.T(), ts, "missing token string value")
	assert.NotNil(s.T(), t, "missing token value")

	claims := t.Claims.(*service.CommonClaims)
	assert.NotNil(s.T(), claims.Data, "missing data claim")
	type XData struct {
		IDList []string `json:"cms_ids"`
	}

	var xData XData
	d, err := strconv.Unquote(claims.Data)
	require.Nil(s.T(), err, "couldn't unquote ", d)
	err = json.Unmarshal([]byte(d), &xData)
	require.Nil(s.T(), err, "unexpected error in: ", d)
	require.NotEmpty(s.T(), xData, "no data in data :(")
	assert.Equal(s.T(), 2, len(xData.IDList))
	assert.Equal(s.T(), "T67890", xData.IDList[0])
	assert.Equal(s.T(), "T54321", xData.IDList[1])
}

func (s *PublicTokenTestSuite) TestCheckTokenClaimsMissingType() {
	tests := []struct {
		name  string
		claim service.CommonClaims
		err   string
	}{
		{"No token type", service.CommonClaims{}, "missing token type claim"},
		{"MFAToken", service.CommonClaims{TokenType: "MFAToken"}, "MFA token must have OktaID claim"},
		{"RegistrationToken", service.CommonClaims{TokenType: "RegistrationToken"}, "registration token must have GroupIDs claim"},
		{"AccessToken", service.CommonClaims{TokenType: "AccessToken"}, "access token must have Data claim"},
	}

	for _, tt := range tests {
		s.T().Run(tt.name, func(t *testing.T) {
			err := checkTokenClaims(&tt.claim)
			if err == nil {
				assert.FailNow(s.T(), "must have error with missing token type")
			}
			assert.Contains(s.T(), err.Error(), tt.err)
		})
	}

}

func (s *PublicTokenTestSuite) TestEmpty() {
	groupIDs := []string{"", ""}
	assert.True(s.T(), empty(groupIDs))

	groupIDs = []string{"", "asdf"}
	assert.False(s.T(), empty(groupIDs))
}

func TestPublicTokenTestSuite(t *testing.T) {
	suite.Run(t, new(PublicTokenTestSuite))
}

package ssas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

const SampleGroup string = `{
  "group_id":"%s",
  "name": "ACO Corp Systems",
  "resources": [
    {
      "id": "xxx",
      "name": "BCDA API",
      "scopes": [
        "bcda-api"
      ]
    },
    {
      "id": "eft",
      "name": "EFT CCLF",
      "scopes": [
        "eft-app:download",
        "eft-data:read"
      ]
    }
  ],
  "scopes": [
    "user-admin",
    "system-admin"
  ],
  "users": [
    "00uiqolo7fEFSfif70h7",
    "l0vckYyfyow4TZ0zOKek",
    "HqtEi2khroEZkH4sdIzj"
  ],
  "systems": [],
  "xdata": %s
}`

const SampleXdata string = `"{\"cms_ids\":[\"T67890\",\"T54321\"]}"`

type GroupsTestSuite struct {
	suite.Suite
	db *gorm.DB
	r  *GormGroupRepository
}

func (s *GroupsTestSuite) SetupTest() {
	var err error
	s.db, err = CreateDB()
	require.NoError(s.T(), err)
	s.r = NewGroupRepository(s.db)
}

// skipAuthContext returns a context that skips SGA authorization for tests
func (s *GroupsTestSuite) skipAuthContext() context.Context {
	return context.WithValue(context.Background(), constants.CtxSGASkipAuthKey, "true")
}

func (s *GroupsTestSuite) TearDownTest() {
	db, err := s.db.DB()
	require.NoError(s.T(), err)
	err = db.Close()
	require.NoError(s.T(), err)

}

func TestGroupsTestSuite(t *testing.T) {
	suite.Run(t, new(GroupsTestSuite))
}

func (s *GroupsTestSuite) TestCreateGroup() {
	gid := RandomHexID()
	gd := GroupData{}
	err := json.Unmarshal([]byte(fmt.Sprintf(SampleGroup, gid, SampleXdata)), &gd)
	assert.Nil(s.T(), err)

	g, err := s.r.CreateGroup(s.skipAuthContext(), gd)

	require.Nil(s.T(), err)
	require.NotNil(s.T(), g)
	assert.NotZero(s.T(), g.ID)
	assert.Equal(s.T(), gid, g.GroupID)
	assert.Equal(s.T(), gid, g.Data.GroupID)
	assert.Equal(s.T(), 3, len(g.Data.Users))
	assert.NotEmpty(s.T(), g.XData)
	assert.NotEmpty(s.T(), g.Data.XData)
	assert.Equal(s.T(), g.Data.XData, g.XData)

	dbGroup := Group{}
	if err := s.db.First(&dbGroup, g.ID).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		assert.FailNow(s.T(), fmt.Sprintf("record not found for id=%d", g.ID))
	}
	assert.Equal(s.T(), gid, dbGroup.GroupID)
	assert.Equal(s.T(), gid, dbGroup.Data.GroupID)
	assert.Equal(s.T(), g.XData, dbGroup.XData)
	assert.Equal(s.T(), g.Data, dbGroup.Data)
	assert.Equal(s.T(), dbGroup.Data.XData, dbGroup.XData)

	err = CleanDatabase(g)
	assert.Nil(s.T(), err)
	gd.GroupID = ""
	_, err = s.r.CreateGroup(context.Background(), gd)
	assert.EqualError(s.T(), err, "group_id cannot be blank")
}

func (s *GroupsTestSuite) TestListGroups() {
	var startingCount int64
	s.db.Table("groups").Count(&startingCount)
	groupBytes := []byte(fmt.Sprintf(SampleGroup, RandomHexID(), SampleXdata))
	gd := GroupData{}
	err := json.Unmarshal(groupBytes, &gd)
	require.Nil(s.T(), err)

	g1, err := s.r.CreateGroup(s.skipAuthContext(), gd)
	require.Nil(s.T(), err)

	gd.GroupID = RandomHexID()
	gd.Name = "some-fake-name"
	g2, err := s.r.CreateGroup(s.skipAuthContext(), gd)
	assert.Nil(s.T(), err)

	groupList, err := s.r.ListGroups(s.skipAuthContext())
	assert.Nil(s.T(), err)
	assert.Len(s.T(), groupList.Groups, int(2+startingCount))

	err = CleanDatabase(g1)
	assert.Nil(s.T(), err)
	err = CleanDatabase(g2)
	assert.Nil(s.T(), err)

	groupList, err = s.r.ListGroups(s.skipAuthContext())
	assert.Nil(s.T(), err)
	assert.Len(s.T(), groupList.Groups, int(startingCount))
}

func (s *GroupsTestSuite) TestListGroups_WithSGA() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, constants.CtxSGAKey, "unique-sga")

	// create 3 groups
	// group 1 multiple systems, some unauth
	// group 2 no auth systems
	// group 3 no systems
	g1Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-1", SampleXdata))
	gd1 := GroupData{}
	err := json.Unmarshal(g1Bytes, &gd1)
	assert.Nil(s.T(), err)
	g1, err := s.r.CreateGroup(s.skipAuthContext(), gd1)
	assert.Nil(s.T(), err)

	g2Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-2", SampleXdata))
	gd2 := GroupData{}
	err = json.Unmarshal(g2Bytes, &gd2)
	assert.Nil(s.T(), err)
	g2, err := s.r.CreateGroup(s.skipAuthContext(), gd2)
	assert.Nil(s.T(), err)

	g3Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-3", SampleXdata))
	gd3 := GroupData{}
	err = json.Unmarshal(g3Bytes, &gd3)
	assert.Nil(s.T(), err)
	g3, err := s.r.CreateGroup(s.skipAuthContext(), gd3)
	assert.Nil(s.T(), err)

	// create 3 systems
	// 2 associated with group 1, one auth, one unauthed
	// 1 associated with group 2, no auth
	g1AuthSys := System{GID: g1.ID, GroupID: "group-id-1", ClientID: "c-id-1", SGAKey: "unique-sga"}
	err = s.db.Create(&g1AuthSys).Error
	assert.Nil(s.T(), err, "unexpected error")

	g1UnauthSys := System{GID: g1.ID, GroupID: "group-id-1", ClientID: "c-id-2", SGAKey: "different-sga"}
	err = s.db.Create(&g1UnauthSys).Error
	assert.Nil(s.T(), err, "unexpected error")

	g2UnauthSys := System{GID: g2.ID, GroupID: "group-id-2", ClientID: "c-id-3", SGAKey: "different-sga"}
	err = s.db.Create(&g2UnauthSys).Error
	assert.Nil(s.T(), err, "unexpected error")

	s.T().Cleanup(func() {
		err = CleanDatabase(g1)
		assert.Nil(s.T(), err)
		err = CleanDatabase(g2)
		assert.Nil(s.T(), err)
		err = CleanDatabase(g3)
		assert.Nil(s.T(), err)
	})

	// verify only group 1 is returned, and only has auth system
	groupList, err := s.r.ListGroups(ctx)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), len(groupList.Groups), 1)
	assert.Equal(s.T(), groupList.Groups[0].ID, g1.ID)
	assert.Equal(s.T(), groupList.Groups[0].GroupID, "group-id-1")
	assert.Equal(s.T(), groupList.Groups[0].Systems[0].SGAKey, "unique-sga")
}

func (s *GroupsTestSuite) TestUpdateGroup() {
	gid1 := RandomHexID()
	groupBytes := []byte(fmt.Sprintf(SampleGroup, gid1, SampleXdata))
	gd := GroupData{}
	err := json.Unmarshal(groupBytes, &gd)
	assert.Nil(s.T(), err)
	orig := Group{}
	orig.Data = gd
	err = s.db.Save(&orig).Error
	require.Nil(s.T(), err)

	gd.Scopes = []string{"aScope", "anotherScope"}
	gd.GroupID = RandomHexID()
	gd.Name = "aNewGroupName"

	changed, err := s.r.UpdateGroup(s.skipAuthContext(), fmt.Sprint(orig.ID), gd)
	assert.Nil(s.T(), err)

	assert.Nil(s.T(), err)
	assert.Equal(s.T(), []string{"aScope", "anotherScope"}, changed.Data.Scopes)
	assert.NotEqual(s.T(), "aNewGroupID", changed.Data.GroupID)
	assert.NotEqual(s.T(), "aNewGroupName", changed.Data.Name)
	err = CleanDatabase(orig)
	assert.Nil(s.T(), err)
}

func (s *GroupsTestSuite) TestDeleteGroup() {
	gid := fmt.Sprintf("delete-group-%s", RandomHexID())
	group := Group{GroupID: gid}
	err := s.db.Create(&group).Error
	require.Nil(s.T(), err, "unexpected error")

	system := System{GID: group.ID, ClientID: "groups-test-delete-client-id"}
	err = s.db.Create(&system).Error
	require.Nil(s.T(), err, "unexpected error")

	keyStr := "publickey"
	encrKey := EncryptionKey{
		SystemID: system.ID,
		Body:     keyStr,
	}
	err = s.db.Create(&encrKey).Error
	require.Nil(s.T(), err, "unexpected error")

	err = s.r.DeleteGroup(s.skipAuthContext(), fmt.Sprint(group.ID))
	assert.Nil(s.T(), err)
	err = CleanDatabase(group)
	assert.Nil(s.T(), err)
}

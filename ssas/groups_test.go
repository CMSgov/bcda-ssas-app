package ssas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
}

func (s *GroupsTestSuite) SetupSuite() {
	s.db = Connection
}

func (s *GroupsTestSuite) AfterTest() {
}

func (s *GroupsTestSuite) TestCreateGroup() {
	gid := RandomHexID()
	gd := GroupData{}
	err := json.Unmarshal([]byte(fmt.Sprintf(SampleGroup, gid, SampleXdata)), &gd)
	assert.Nil(s.T(), err)
	g, err := CreateGroup(context.Background(), gd)

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
	if err := Connection.First(&dbGroup, g.ID).Error; errors.Is(err, gorm.ErrRecordNotFound) {
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
	_, err = CreateGroup(context.Background(), gd)
	assert.EqualError(s.T(), err, "group_id cannot be blank")
}

func (s *GroupsTestSuite) TestListGroups() {
	var startingCount int64
	Connection.Table("groups").Count(&startingCount)
	groupBytes := []byte(fmt.Sprintf(SampleGroup, RandomHexID(), SampleXdata))
	gd := GroupData{}
	err := json.Unmarshal(groupBytes, &gd)
	require.Nil(s.T(), err)
	g1, err := CreateGroup(context.Background(), gd)
	require.Nil(s.T(), err)

	gd.GroupID = RandomHexID()
	gd.Name = "some-fake-name"
	g2, err := CreateGroup(context.Background(), gd)
	assert.Nil(s.T(), err)

	groupList, err := ListGroups(context.Background())
	assert.Nil(s.T(), err)
	assert.Len(s.T(), groupList.Groups, int(2+startingCount))

	err = CleanDatabase(g1)
	assert.Nil(s.T(), err)
	err = CleanDatabase(g2)
	assert.Nil(s.T(), err)

	groupList, err = ListGroups(context.Background())
	assert.Nil(s.T(), err)
	assert.Len(s.T(), groupList.Groups, int(startingCount))
}

func (s *GroupsTestSuite) TestListGroups_With_SGA_ADMIN_FEATURE() {
	ctx := context.Background()
	ctx = context.WithValue(ctx, constants.CtxSGAKey, "test-sga")

	newFF := "true"
	oldFF := os.Getenv("SGA_ADMIN_FEATURE")
	os.Setenv("SGA_ADMIN_FEATURE", newFF)

	// create 3 groups
	// group 1 multiple systems, some unauth
	// group 2 no auth systems
	// group 3 no systems
	g1Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-1", SampleXdata))
	gd1 := GroupData{}
	err := json.Unmarshal(g1Bytes, &gd1)
	assert.Nil(s.T(), err)
	g1, err := CreateGroup(context.Background(), gd1)
	assert.Nil(s.T(), err)

	g2Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-2", SampleXdata))
	gd2 := GroupData{}
	err = json.Unmarshal(g2Bytes, &gd2)
	assert.Nil(s.T(), err)
	g2, err := CreateGroup(context.Background(), gd2)
	assert.Nil(s.T(), err)

	g3Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-3", SampleXdata))
	gd3 := GroupData{}
	err = json.Unmarshal(g3Bytes, &gd3)
	assert.Nil(s.T(), err)
	g3, err := CreateGroup(context.Background(), gd3)
	assert.Nil(s.T(), err)

	// create 3 systems
	// 2 associated with group 1, one auth, one unauthed
	// 1 associated with group 2, no auth
	g1AuthSys := System{GID: g1.ID, GroupID: "group-id-1", ClientID: "c-id-1", SGAKey: "test-sga"}
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
		os.Setenv("SGA_ADMIN_FEATURE", oldFF)
	})

	// verify only group 1 is returned, and only has auth system
	groupList, err := ListGroups(ctx)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), len(groupList.Groups), 1)
	assert.Equal(s.T(), groupList.Groups[0].ID, g1.ID)
	assert.Equal(s.T(), groupList.Groups[0].GroupID, "group-id-1")
	assert.Equal(s.T(), groupList.Groups[0].Systems[0].SGAKey, "test-sga")
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
	changed, err := UpdateGroup(context.Background(), fmt.Sprint(orig.ID), gd)
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

	err = DeleteGroup(context.Background(), fmt.Sprint(group.ID))
	assert.Nil(s.T(), err)
	err = CleanDatabase(group)
	assert.Nil(s.T(), err)
}

// func (s *GroupsTestSuite) TestGetGroupByGroupID_With_SGA_ADMIN_FEATURE() {
// 	ctx := context.Background()
// 	ctx = context.WithValue(ctx, constants.CtxSGAKey, "test-sga")

// 	newFF := "true"
// 	oldFF := os.Getenv("SGA_ADMIN_FEATURE")
// 	os.Setenv("SGA_ADMIN_FEATURE", newFF)

// 	// create 2 groups, 1 with auth system, 1 with unauth system
// 	g1Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-1", SampleXdata))
// 	gd1 := GroupData{}
// 	err := json.Unmarshal(g1Bytes, &gd1)
// 	assert.Nil(s.T(), err)
// 	g1, err := CreateGroup(context.Background(), gd1)
// 	assert.Nil(s.T(), err)

// 	g1AuthSys := System{GID: g1.ID, GroupID: "group-id-1", ClientID: "test-g1", SGAKey: "test-sga"}
// 	err = s.db.Create(&g1AuthSys).Error
// 	assert.Nil(s.T(), err, "unexpected error")

// 	g2Bytes := []byte(fmt.Sprintf(SampleGroup, "group-id-2", SampleXdata))
// 	gd2 := GroupData{}
// 	err = json.Unmarshal(g2Bytes, &gd2)
// 	assert.Nil(s.T(), err)
// 	g2, err := CreateGroup(context.Background(), gd2)
// 	assert.Nil(s.T(), err)

// 	g2UnauthSys := System{GID: g2.ID, GroupID: "group-id-2", ClientID: "test-g2", SGAKey: "different-sga"}
// 	err = s.db.Create(&g2UnauthSys).Error
// 	assert.Nil(s.T(), err, "unexpected error")

// 	s.T().Cleanup(func() {
// 		err = CleanDatabase(g1)
// 		assert.Nil(s.T(), err)
// 		err = CleanDatabase(g2)
// 		assert.Nil(s.T(), err)
// 		os.Setenv("SGA_ADMIN_FEATURE", oldFF)
// 	})

// 	foundG1, err := GetGroupByGroupID(ctx, "group-id-1")
// 	assert.Nil(s.T(), err)
// 	assert.Equal(s.T(), foundG1.ID, g1.ID)

// 	foundG2, err := GetGroupByGroupID(ctx, "group-id-2")
// 	assert.ErrorContains(s.T(), err, "error finding authorized system(s) related to groupID")
// 	assert.Equal(s.T(), foundG2.ID, Group{}.ID)
// }

// func (s *GroupsTestSuite) TestGetAuthorizedGroupsForOktaID() {
// 	group1bytes := []byte(`{"group_id":"T0001","users":["abcdef","qrstuv"],"scopes":[],"resources":[],"systems":[],"name":""}`)
// 	group2bytes := []byte(`{"group_id":"T0002","users":["abcdef","qrstuv"],"scopes":[],"resources":[],"systems":[],"name":""}`)
// 	group3bytes := []byte(`{"group_id":"T0003","users":["qrstuv"],"scopes":[],"resources":[],"systems":[],"name":""}`)

// 	g1 := GroupData{}
// 	err := json.Unmarshal(group1bytes, &g1)
// 	assert.Nil(s.T(), err)
// 	group1, _ := CreateGroup(context.Background(), g1)

// 	g2 := GroupData{}
// 	err = json.Unmarshal(group2bytes, &g2)
// 	assert.Nil(s.T(), err)
// 	group2, _ := CreateGroup(context.Background(), g2)

// 	g3 := GroupData{}
// 	err = json.Unmarshal(group3bytes, &g3)
// 	assert.Nil(s.T(), err)
// 	group3, _ := CreateGroup(context.Background(), g3)

// 	defer s.db.Unscoped().Delete(&group1)
// 	defer s.db.Unscoped().Delete(&group2)
// 	defer s.db.Unscoped().Delete(&group3)

// 	authorizedGroups, err := GetAuthorizedGroupsForOktaID(context.Background(), "abcdef")
// 	if err != nil {
// 		s.FailNow(err.Error())
// 	}
// 	if len(authorizedGroups) != 2 {
// 		s.FailNow("oktaID should be authorized for exactly two groups")
// 	}
// 	assert.Equal(s.T(), "T0001", authorizedGroups[0])
// }

func TestGroupsTestSuite(t *testing.T) {
	suite.Run(t, new(GroupsTestSuite))
}

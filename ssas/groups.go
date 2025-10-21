package ssas

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/CMSgov/bcda-ssas-app/ssas/constants"
	"gorm.io/gorm"
)

type Group struct {
	gorm.Model
	GroupID string    `gorm:"unique;not null" json:"group_id"`
	XData   string    `gorm:"type:text" json:"xdata"`
	Data    GroupData `gorm:"type:jsonb" json:"data"`
	Systems []System  `gorm:"foreignkey:GID"`
}

type SystemSummary struct {
	ID         uint      `json:"id"`
	GID        uint      `json:"-"`
	ClientName string    `json:"client_name"`
	ClientID   string    `json:"client_id"`
	IPs        []string  `json:"ips,omitempty" gorm:"-"`
	UpdatedAt  time.Time `json:"updated_at"`
	SGAKey     string    `json:"sga_key"`
}

func (SystemSummary) TableName() string {
	return "systems"
}

type GroupSummary struct {
	ID        uint            `json:"id"`
	GroupID   string          `json:"group_id"`
	XData     string          `json:"xdata"`
	CreatedAt time.Time       `json:"created_at"`
	Systems   []SystemSummary `json:"systems" gorm:"foreignkey:GID;association_foreignkey:ID"`
}

func (GroupSummary) TableName() string {
	return "groups"
}

type GroupList struct {
	Count      int            `json:"count"`
	ReportedAt time.Time      `json:"reported_at"`
	Groups     []GroupSummary `json:"groups"`
}

type GroupData struct {
	GroupID   string     `json:"group_id"`
	Name      string     `json:"name"`
	XData     string     `json:"xdata"`
	Users     []string   `json:"users,omitempty"`
	Scopes    []string   `json:"scopes,omitempty"`
	Systems   []System   `gorm:"-" json:"systems,omitempty"`
	Resources []Resource `json:"resources,omitempty"`
}

// Value implements the driver.Value interface for GroupData.
func (gd GroupData) Value() (driver.Value, error) {
	// TODO: pull from configurable setting for db timeout
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	systems, _ := GetSystemsByGroupIDString(timeoutCtx, gd.GroupID)

	gd.Systems = systems

	return json.Marshal(gd)
}

// Make the GroupData struct implement the sql.Scanner interface
func (gd *GroupData) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}

	if err := json.Unmarshal(b, &gd); err != nil {
		return err
	}

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	systems, _ := GetSystemsByGroupIDString(timeoutCtx, gd.GroupID)
	gd.Systems = systems

	return nil
}

type Resource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Example: ["bcda-api"]
	Scopes []string `json:"scopes"`
}

type GroupRepository struct {
	db *gorm.DB
}

func NewGroupRepository(db *gorm.DB) *GroupRepository {
	return &GroupRepository{db: db}
}

func (g *GroupRepository) CreateGroup(ctx context.Context, gd GroupData) (Group, error) {
	if gd.GroupID == "" {
		err := fmt.Errorf("group_id cannot be blank")
		return Group{}, err
	}
	xd := gd.XData
	if xd != "" {
		if s, err := strconv.Unquote(xd); err == nil {
			xd = s
		}
	}
	group := Group{
		GroupID: gd.GroupID,
		XData:   xd,
		Data:    gd,
	}
	err := g.db.WithContext(ctx).Save(&group).Error
	if err != nil {
		return Group{}, err
	}
	return group, nil
}

func (g *GroupRepository) ListGroups(ctx context.Context) (list GroupList, err error) {
	groups := []GroupSummary{}
	err = g.db.WithContext(ctx).Table("groups").Where("deleted_at IS NULL").Preload("Systems").Find(&groups).Error
	if err != nil {
		return list, err
	}
	list.Count = len(groups)
	list.ReportedAt = time.Now()

	skipSGAAuthCheck := fmt.Sprintf("%v", ctx.Value(constants.CtxSGASkipAuthKey))
	if skipSGAAuthCheck != "true" {
		requesterSGAKey := fmt.Sprintf("%v", ctx.Value(constants.CtxSGAKey))

		groups = slices.DeleteFunc(groups, func(group GroupSummary) bool {
			// remove all unauthorized systems
			group.Systems = slices.DeleteFunc(group.Systems, func(system SystemSummary) bool {
				return system.SGAKey != requesterSGAKey
			})

			// remove group if no authorized systems
			return len(group.Systems) == 0
		})
	}

	list.Groups = groups
	return list, nil
}

func (g *GroupRepository) UpdateGroup(ctx context.Context, id string, gd GroupData) (Group, error) {
	group, err := g.GetGroupByID(ctx, id)
	if err != nil {
		err := fmt.Errorf("record not found for id=%s", id)
		return Group{}, err
	}
	gd.GroupID = group.Data.GroupID
	gd.Name = group.Data.Name
	group.Data = gd
	err = g.db.WithContext(ctx).Save(&group).Error
	if err != nil {
		return Group{}, fmt.Errorf("group failed to meet database constraints")
	}
	return group, nil
}

func (g *GroupRepository) DeleteGroup(ctx context.Context, id string) error {
	group, err := g.GetGroupByID(ctx, id)
	if err != nil {
		return err
	}
	err = g.cascadeDeleteGroup(ctx, group)
	if err != nil {
		return err
	}
	return nil
}

func (g *GroupRepository) cascadeDeleteGroup(ctx context.Context, group Group) error {
	var (
		system        System
		encryptionKey EncryptionKey
		secret        Secret
		systemIds     []int
	)

	tx := g.db.WithContext(ctx).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	tx.Table("systems").Where("group_id = ?", group.GroupID).Pluck("id", &systemIds)
	tx.Where("system_id IN (?)", systemIds).Delete(&encryptionKey)
	tx.Where("system_id IN (?)", systemIds).Delete(&secret)
	tx.Where("id IN (?)", systemIds).Delete(&system)
	tx.Delete(&group)

	err := tx.Commit().Error
	if err != nil {
		return fmt.Errorf("unable to delete group: %s", err.Error())
	}

	return nil
}

func (g *GroupRepository) GetGroupByGroupID(ctx context.Context, groupID string) (Group, error) {
	var (
		group Group
		err   error
	)

	if err = g.db.WithContext(ctx).First(&group, "group_id = ?", groupID).Error; err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		err = fmt.Errorf("no Group record found for groupID %s", groupID)
	}

	return group, err
}

// GetGroupByID returns the group associated with the provided ID
func (g *GroupRepository) GetGroupByID(ctx context.Context, id string) (Group, error) {
	var (
		group Group
		err   error
	)

	id1, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return Group{}, fmt.Errorf("invalid input %s; %s", id, err)
	}

	if err = g.db.WithContext(ctx).First(&group, id1).Error; err != nil {
		err = fmt.Errorf("no Group record found with ID %s", id)
	}

	skipSGAAuthCheck := fmt.Sprintf("%v", ctx.Value(constants.CtxSGASkipAuthKey))
	if skipSGAAuthCheck != "true" {
		sgaKeyFromGroupID, err := GetSGAKeyByGroupID(ctx, g.db, group.GroupID)
		requesterSGAKey := fmt.Sprintf("%v", ctx.Value(constants.CtxSGAKey))

		if err != nil || sgaKeyFromGroupID != requesterSGAKey {
			return Group{}, fmt.Errorf("error authorizing requesting system (%+v) to group with groupID: %v, err: %+v", requesterSGAKey, group.GroupID, err)
		}
	}

	return group, err
}

// DataForSystem returns the group extra data associated with this system
func (g *GroupRepository) XDataFor(ctx context.Context, system System) (string, error) {
	if system.GID > math.MaxInt {
		return "", fmt.Errorf("group id uint overflow converting to int")
	}
	group, err := g.GetGroupByID(ctx, strconv.Itoa(int(system.GID)))
	if err != nil {
		return "", fmt.Errorf("no group for system %d; %s", system.ID, err)
	}
	return group.XData, nil
}

package ssas

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

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

type Resource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Example: ["bcda-api"]
	Scopes []string `json:"scopes"`
}

func CreateGroup(ctx context.Context, gd GroupData) (Group, error) {
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
	g := Group{
		GroupID: gd.GroupID,
		XData:   xd,
		Data:    gd,
	}
	err := Connection.WithContext(ctx).Save(&g).Error
	if err != nil {
		return Group{}, err
	}
	return g, nil
}

func ListGroups(ctx context.Context) (list GroupList, err error) {
	groups := []GroupSummary{}
	err = Connection.WithContext(ctx).Table("groups").Where("deleted_at IS NULL").Preload("Systems").Find(&groups).Error
	if err != nil {
		return list, err
	}
	list.Count = len(groups)
	list.ReportedAt = time.Now()
	list.Groups = groups
	return list, nil
}

func UpdateGroup(ctx context.Context, id string, gd GroupData) (Group, error) {
	g, err := GetGroupByID(ctx, id)
	if err != nil {
		err := fmt.Errorf("record not found for id=%s", id)
		return Group{}, err
	}
	gd.GroupID = g.Data.GroupID
	gd.Name = g.Data.Name
	g.Data = gd
	err = Connection.WithContext(ctx).Save(&g).Error
	if err != nil {
		return Group{}, fmt.Errorf("group failed to meet database constraints")
	}
	return g, nil
}

func DeleteGroup(ctx context.Context, id string) error {
	g, err := GetGroupByID(ctx, id)
	if err != nil {
		return err
	}
	err = cascadeDeleteGroup(ctx, g)
	if err != nil {
		return err
	}
	return nil
}

// GetAuthorizedGroupsForOktaID returns a slice of GroupID's representing all groups this Okta user has rights to manage
// TODO: this is the slowest and most memory intensive way possible to implement this.  Refactor!
func GetAuthorizedGroupsForOktaID(ctx context.Context, oktaID string) ([]string, error) {
	var (
		result []string
	)

	groups := []Group{}
	err := Connection.WithContext(ctx).Select("*").Find(&groups).Error
	if err != nil {
		return result, err
	}

	for _, group := range groups {
		for _, user := range group.Data.Users {
			if user == oktaID {
				result = append(result, group.GroupID)
			}
		}
	}

	return result, nil
}

func cascadeDeleteGroup(ctx context.Context, group Group) error {
	var (
		system        System
		encryptionKey EncryptionKey
		secret        Secret
		systemIds     []int
	)

	tx := Connection.WithContext(ctx).Begin()
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

func GetGroupByGroupID(ctx context.Context, groupID string) (Group, error) {
	var (
		group Group
		err   error
	)

	if err = Connection.WithContext(ctx).First(&group, "group_id = ?", groupID).Error; err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		err = fmt.Errorf("no Group record found for groupID %s", groupID)
	}

	return group, err
}

// GetGroupByID returns the group associated with the provided ID
func GetGroupByID(ctx context.Context, id string) (Group, error) {
	var (
		group Group
		err   error
	)

	id1, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return Group{}, fmt.Errorf("invalid input %s; %s", id, err)
	}

	if err = Connection.WithContext(ctx).First(&group, id1).Error; err != nil {
		err = fmt.Errorf("no Group record found with ID %s", id)
	}
	return group, err
}

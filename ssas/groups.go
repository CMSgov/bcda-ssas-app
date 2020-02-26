package ssas

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jinzhu/gorm"
	"strconv"
	"time"
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
	IPs        []string  `json:"ips,omitempty"`
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
	Systems   []SystemSummary `json:"systems" gorm:"foreignkey:GID"`
}

func (GroupSummary) TableName() string {
	return "groups"
}

type GroupList struct {
	Count      int            `json:"count"`
	ReportedAt time.Time      `json:"reported_at"`
	Groups     []GroupSummary `json:"groups"`
}

func CreateGroup(gd GroupData, trackingID string) (Group, error) {
	event := Event{Op: "CreateGroup", TrackingID: trackingID}
	OperationStarted(event)

	if gd.GroupID == "" {
		err := fmt.Errorf("group_id cannot be blank")
		event.Help = err.Error()
		OperationFailed(event)
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

	db := GetGORMDbConnection()
	defer Close(db)
	err := db.Save(&g).Error
	if err != nil {
		event.Help = err.Error()
		OperationFailed(event)
		return Group{}, fmt.Errorf("group violates uniqueness or other constraints")
	}

	OperationSucceeded(event)
	return g, nil
}

func ListGroups(trackingID string) (list GroupList, err error) {
	event := Event{Op: "ListGroups", TrackingID: trackingID}
	OperationStarted(event)

	groups := []GroupSummary{}
	db := GetGORMDbConnection()
	defer Close(db)
	err = db.Preload("Systems").Where("deleted_at IS NULL").Find(&groups).Error
	if err != nil {
		event.Help = err.Error()
		OperationFailed(event)
		return
	}

	list.Count = len(groups)
	list.ReportedAt = time.Now()
	list.Groups = groups

	OperationSucceeded(event)
	return list, nil
}

func UpdateGroup(id string, gd GroupData) (Group, error) {
	event := Event{Op: "UpdateGroup", TrackingID: id}
	OperationStarted(event)

	db := GetGORMDbConnection()
	defer Close(db)

	g, err := GetGroupByID(id)
	if err != nil {
		errString := fmt.Sprintf("record not found for id=%s", id)
		event.Help = errString + ": " + err.Error()
		err := fmt.Errorf(errString)
		OperationFailed(event)
		return Group{}, err
	}

	gd.GroupID = g.Data.GroupID
	gd.Name = g.Data.Name

	g.Data = gd
	err = db.Save(&g).Error
	if err != nil {
		event.Help = err.Error()
		OperationFailed(event)
		return Group{}, fmt.Errorf("group failed to meet database constraints")
	}

	OperationSucceeded(event)
	return g, nil
}

func DeleteGroup(id string) error {
	event := Event{Op: "DeleteGroup", TrackingID: id}
	OperationStarted(event)

	db := GetGORMDbConnection()
	defer Close(db)
	g, err := GetGroupByID(id)
	if err != nil {
		event.Help = err.Error()
		OperationFailed(event)
		return err
	}

	err = cascadeDeleteGroup(g)
	if err != nil {
		event.Help = err.Error()
		OperationFailed(event)
		return fmt.Errorf("database error")
	}

	OperationSucceeded(event)
	return nil
}

// GetAuthorizedGroupsForOktaID returns a slice of GroupID's representing all groups this Okta user has rights to manage
// TODO: this is the slowest and most memory intensive way possible to implement this.  Refactor!
func GetAuthorizedGroupsForOktaID(oktaID string) ([]string, error) {
	db := GetGORMDbConnection()
	defer Close(db)

	var (
		result []string
	)

	groups := []Group{}
	err := db.Select("*").Find(&groups).Error
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

func cascadeDeleteGroup(group Group) error {
	var (
		system        System
		encryptionKey EncryptionKey
		secret        Secret
		systemIds     []int
		db            = GetGORMDbConnection()
	)
	defer Close(db)

	err := db.Table("systems").Where("group_id = ?", group.GroupID).Pluck("ID", &systemIds).Error
	if err != nil {
		return fmt.Errorf("unable to find associated systems: %s", err.Error())
	}

	err = db.Where("system_id IN (?)", systemIds).Delete(&encryptionKey).Error
	if err != nil {
		return fmt.Errorf("unable to delete encryption keys: %s", err.Error())
	}

	err = db.Where("system_id IN (?)", systemIds).Delete(&secret).Error
	if err != nil {
		return fmt.Errorf("unable to delete secrets: %s", err.Error())
	}

	err = db.Where("id IN (?)", systemIds).Delete(&system).Error
	if err != nil {
		return fmt.Errorf("unable to delete systems: %s", err.Error())
	}

	err = db.Delete(&group).Error
	if err != nil {
		return fmt.Errorf("unable to delete group: %s", err.Error())
	}

	return nil
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
	systems, _ := GetSystemsByGroupIDString(gd.GroupID)

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
	systems, _ := GetSystemsByGroupIDString(gd.GroupID)

	gd.Systems = systems

	return nil
}

type Resource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Example: ["bcda-api"]
	Scopes []string `json:"scopes"`
}

func GetGroupByGroupID(groupID string) (Group, error) {
	var (
		db    = GetGORMDbConnection()
		group Group
		err   error
	)
	defer Close(db)

	if db.Find(&group, "group_id = ?", groupID).RecordNotFound() {
		err = fmt.Errorf("no Group record found for groupID %s", groupID)
	}

	return group, err
}

// GetGroupByID returns the group associated with the provided ID
func GetGroupByID(id string) (Group, error) {
	var (
		db    = GetGORMDbConnection()
		group Group
		err   error
	)
	defer Close(db)

	if _, err = strconv.ParseUint(id, 10, 64); err != nil {
		return Group{}, fmt.Errorf("invalid input %s; %s", id, err)
	}
	// must use the explicit where clause here because the id argument is a string
	if err = db.Find(&group, "id = ?", id).Error; err != nil {
		err = fmt.Errorf("no Group record found with ID %s", id)
	}
	return group, err
}

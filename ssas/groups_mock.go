package ssas

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type GroupRepositoryMock struct {
	mock.Mock
}

func (m *GroupRepositoryMock) CreateGroup(ctx context.Context, gd GroupData) (Group, error) {
	args := m.Called(ctx, gd)
	return args.Get(0).(Group), args.Error(1)
}

func (m *GroupRepositoryMock) DeleteGroup(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *GroupRepositoryMock) GetGroupByGroupID(ctx context.Context, groupID string) (Group, error) {
	args := m.Called(ctx, groupID)
	return args.Get(0).(Group), args.Error(1)
}

func (m *GroupRepositoryMock) GetGroupByID(ctx context.Context, id string) (Group, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(Group), args.Error(1)
}

func (m *GroupRepositoryMock) ListGroups(ctx context.Context) (list GroupList, err error) {
	args := m.Called(ctx)
	return args.Get(0).(GroupList), args.Error(1)
}

func (m *GroupRepositoryMock) UpdateGroup(ctx context.Context, id string, gd GroupData) (Group, error) {
	args := m.Called(ctx, id, gd)
	return args.Get(0).(Group), args.Error(1)
}

func (m *GroupRepositoryMock) XDataFor(ctx context.Context, system System) (string, error) {
	args := m.Called(ctx, system)
	return args.Get(0).(string), args.Error(1)
}

func (m *GroupRepositoryMock) cascadeDeleteGroup(ctx context.Context, group Group) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}

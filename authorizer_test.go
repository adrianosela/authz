package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hasPermissionOnResource(t *testing.T) {
	mockEntity := "mock-entity"
	mockResource := "mock-resource"
	mockPermission := "mock-permission"

	tests := []struct {
		name              string
		db                map[string]resourcePermissions
		checkedEntity     string
		checkedResource   string
		checkedPermission string
		expected          bool
	}{
		{
			name: "Allowed when entity has resource permission",
			db: map[string]resourcePermissions{
				mockEntity: map[string][]string{
					mockResource: {
						mockPermission,
					},
				},
			},
			checkedEntity:     mockEntity,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          true,
		},
		{
			name: "Not allowed when entity does not have resource permission",
			db: map[string]resourcePermissions{
				mockEntity: map[string][]string{
					mockResource: { /* empty */ },
				},
			},
			checkedEntity:     mockEntity,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          false,
		},
		{
			name: "Not allowed when entity does not have resource",
			db: map[string]resourcePermissions{
				mockEntity: map[string][]string{ /* empty */ },
			},
			checkedEntity:     mockEntity,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          false,
		},
		{
			name:              "Not allowed when entity is not defined",
			db:                map[string]resourcePermissions{ /* empty */ },
			checkedEntity:     mockEntity,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          false,
		},
	}

	for _, test := range tests {
		result := hasPermissionOnResource(test.checkedEntity, test.db, test.checkedResource, test.checkedPermission)
		assert.Equal(t, test.expected, result, test.name)
	}
}

func Test_Authorize(t *testing.T) {
	mockUser := "mock-entity"
	mockGroupA, mockGroupB, mockGroupC := "mock-group-a", "mock-group-b", "mock-group-c"
	mockGroups := []string{mockGroupA, mockGroupB, mockGroupC}
	mockResource := "mock-resource"
	mockPermission := "mock-permission"

	tests := []struct {
		name              string
		authorizer        *Authorizer
		checkedUser       string
		checkedGroups     []string
		checkedResource   string
		checkedPermission string
		expected          bool
	}{
		{
			name: "Allowed when user has resource permission",
			authorizer: &Authorizer{
				Users: map[string]resourcePermissions{
					mockUser: map[string][]string{
						mockResource: {
							mockPermission,
						},
					},
				},
			},
			checkedUser:       mockUser,
			checkedGroups:     mockGroups,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          true,
		},
		{
			name: "Allowed when group has resource permission",
			authorizer: &Authorizer{
				Groups: map[string]resourcePermissions{
					mockGroupC: map[string][]string{
						mockResource: {
							mockPermission,
						},
					},
				},
			},
			checkedUser:       mockUser,
			checkedGroups:     mockGroups,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          true,
		},
		{
			name: "Not allowed when no entities have resource permission",
			authorizer: &Authorizer{
				Users: map[string]resourcePermissions{
					mockUser: map[string][]string{
						mockResource: { /* empty */ },
					},
				},
				Groups: map[string]resourcePermissions{
					mockGroupA: map[string][]string{
						mockResource: { /* empty */ },
					},
					mockGroupB: map[string][]string{
						mockResource: { /* empty */ },
					},
					mockGroupC: map[string][]string{
						mockResource: { /* empty */ },
					},
				},
			},
			checkedUser:       mockUser,
			checkedGroups:     mockGroups,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          false,
		},
		{
			name: "Not allowed when no entities have resource defined",
			authorizer: &Authorizer{
				Users: map[string]resourcePermissions{
					mockUser: map[string][]string{ /* empty */ },
				},
				Groups: map[string]resourcePermissions{
					mockGroupA: map[string][]string{ /* empty */ },
					mockGroupB: map[string][]string{ /* empty */ },
					mockGroupC: map[string][]string{ /* empty */ },
				},
			},
			checkedUser:       mockUser,
			checkedGroups:     mockGroups,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          false,
		},
		{
			name:              "Not allowed when no entities are defined",
			authorizer:        &Authorizer{ /* empty */ },
			checkedUser:       mockUser,
			checkedGroups:     mockGroups,
			checkedResource:   mockResource,
			checkedPermission: mockPermission,
			expected:          false,
		},
	}

	for _, test := range tests {
		result := test.authorizer.Authorize(test.checkedUser, test.checkedGroups, test.checkedResource, test.checkedPermission)
		assert.Equal(t, test.expected, result, test.name)
	}
}

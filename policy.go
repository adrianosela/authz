package authz

// RoleMap is a map of role name to the collection of
// identities that receive the permissions of the role
type RoleMap map[string]struct {
	Users  []string `yaml:"users,omitempty"`
	Groups []string `yaml:"groups,omitempty"`
}

// RoleDefinition represents how a role is defined
type RoleDefinition struct {
	Permissions []string `yaml:"permissions,omitempty"`
	Extends     []string `yaml:"extends,omitempty"`
}

// Policy represents how policies are defined
type Policy struct {
	Roles     map[string]RoleDefinition `yaml:"roles,omitempty"`
	Resources map[string]RoleMap        `yaml:"resources,omitempty"`
}

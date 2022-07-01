package authz

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// mapping of resource name to a set permissions over the resource
type resourcePermissions map[string]set

// Authorizer maintains the compiled authorization data
type Authorizer struct {
	// hash of the source policy yaml file (to check for diffs)
	SourcePolicyHash string `json:"source_policy_hash"`

	// role name to the permissions granted by the role
	Roles map[string]set `json:"roles,omitempty"`

	// user name to resource permissions
	Users map[string]resourcePermissions `json:"users,omitempty"`

	// group name to resource permissions
	Groups map[string]resourcePermissions `json:"groups,omitempty"`
}

const (
	defaultCacheFilename = ".authz.json"
)

// Load loads a policy file onto memory
func Load(fname string) (*Authorizer, error) {
	log.Printf("[authz] <INFO> Loading access control rules...")

	fbytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("Failed to read policy file: %s", err)
	}

	if _, err := os.Stat(defaultCacheFilename); err == nil {
		log.Printf("[authz] <INFO> Cache file %s found, checking hash...", defaultCacheFilename)

		fbytes, err := ioutil.ReadFile(defaultCacheFilename)
		if err != nil {
			return nil, fmt.Errorf("Failed to read cache file: %s", err)
		}

		var a *Authorizer
		if err = json.Unmarshal(fbytes, &a); err != nil {
			return nil, fmt.Errorf("Failed to unmarshal cache file: %s", err)
		}

		if a.SourcePolicyHash == fmt.Sprintf("%x", sha256.Sum256(fbytes)) {
			log.Printf("[authz] <INFO> Hash on cache file matches policy hash, using authz data from cache")

			a.logMetrics()
			return a, nil
		}

		log.Printf("[authz] <INFO> Hash on cache file differs from policy hash, re-processing...")
	}

	log.Printf("[authz] <INFO> Cache file %s not found, processing policy...", defaultCacheFilename)
	start := time.Now()

	var policy *Policy
	if err = yaml.Unmarshal(fbytes, &policy); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal policy file: %s", err)
	}
	a := &Authorizer{SourcePolicyHash: fmt.Sprintf("%x", sha256.Sum256(fbytes))}
	if err = a.compileRoles(policy); err != nil {
		return nil, fmt.Errorf("Failed to compile roles: %s", err)
	}
	if err = a.compileResources(policy); err != nil {
		return nil, fmt.Errorf("Failed to compile resources: %s", err)
	}

	finish := time.Now()
	log.Printf("[authz] <INFO> Policy processing completed. Took %d ns", finish.Sub(start).Nanoseconds())

	if err = a.save(defaultCacheFilename); err != nil {
		log.Printf("[authz] <WARN> Failed to save authorizer to %s: %s", defaultCacheFilename, err)
	} else {
		log.Printf("[authz] <INFO> Saved authorizer cache as %s", defaultCacheFilename)
	}

	a.logMetrics()
	return a, nil
}

// Authorize checks whether a user or set of groups have a permission on a given resource.
// Performance: worst case O(n), where n is the number of groups being checked
func (a *Authorizer) Authorize(user string, groups []string, resource string, permission string) bool {
	if hasPermissionOnResource(user, a.Users, resource, permission) {
		return true
	}
	for _, group := range groups {
		if hasPermissionOnResource(group, a.Groups, resource, permission) {
			return true
		}
	}
	return false
}

// recursive function to compile permissions without cycle detection
func (a *Authorizer) compilePermissions(p *Policy, role string, stack []string) error {
	// check inheriting role exists in policy
	if _, ok := p.Roles[role]; !ok {
		return fmt.Errorf("Role %s not defined. Stack: %s", role, buildStackString(stack))
	}

	// copy base permissions from policy
	a.Roles[role] = newSet(p.Roles[role].Permissions...)

	for _, inheritedRole := range p.Roles[role].Extends {
		// if the inherited role has not been processed, process it
		if _, ok := a.Roles[inheritedRole]; !ok {
			if err := a.compilePermissions(p, inheritedRole, append(stack, inheritedRole)); err != nil {
				return err
			}
		}

		// then copy over the interited perms
		a.Roles[role].join(a.Roles[inheritedRole])
	}

	return nil
}

// recursive function to compile permissions with cycle detection
func (a *Authorizer) compilePermissionsWithCycleDetection(p *Policy, role string, icd set, stack []string) error {
	// check inheriting role exists in policy
	if _, ok := p.Roles[role]; !ok {
		return fmt.Errorf("Role %s not defined. Stack: %s", role, buildStackString(stack))
	}

	// check no cycles in policy
	if icd.has(role) {
		return fmt.Errorf("Inheritance cycle detected. Stack: %s", buildStackString(stack))
	}
	icd.add(role) // mark as seen

	// copy base permissions from policy
	a.Roles[role] = newSet(p.Roles[role].Permissions...)

	for _, inheritedRole := range p.Roles[role].Extends {
		// always process the inherited role (in order to detect cycles)
		if err := a.compilePermissionsWithCycleDetection(p, inheritedRole, icd.copy(), append(stack, inheritedRole)); err != nil {
			return err
		}
		// then copy over the interited perms
		a.Roles[role].join(a.Roles[inheritedRole])
	}

	return nil
}

// compile roles from the policy (definition format) onto the authorizer (consumable format)
func (a *Authorizer) compileRoles(p *Policy) error {
	a.Roles = make(map[string]set)

	for role := range p.Roles {
		if err := a.compilePermissionsWithCycleDetection(p, role, newSet(), []string{role}); err != nil {
			return fmt.Errorf("Failed to compile permissions set for role \"%s\": %s", role, err)
		}
	}

	return nil
}

// compile resources from the policy (definition format) onto the authorizer (consumable format)
func (a *Authorizer) compileResources(p *Policy) error {
	a.Users = make(map[string]resourcePermissions)
	a.Groups = make(map[string]resourcePermissions)

	for resource, rules := range p.Resources {
		for role, identities := range rules {
			// fmt.Printf("Resource: %s, role: %s, identities: %v\n", resource, role, identities)
			for _, user := range identities.Users {
				if _, ok := a.Users[user]; !ok {
					a.Users[user] = make(resourcePermissions)
				}
				if _, ok := a.Users[user][resource]; !ok {
					a.Users[user][resource] = newSet()
				}
				a.Users[user][resource].join(a.Roles[role])
			}
			for _, group := range identities.Groups {
				if _, ok := a.Groups[group]; !ok {
					a.Groups[group] = make(resourcePermissions)
				}
				if _, ok := a.Groups[group][resource]; !ok {
					a.Groups[group][resource] = newSet()
				}
				a.Groups[group][resource].join(a.Roles[role])
			}
		}
	}

	return nil
}

func (a *Authorizer) logMetrics() {
	rolesByteSize, err := getRealSizeOf(a.Roles)
	if err != nil {
		log.Printf("[authz] <WARN> Failed to get the size of the roles map: %s", err)
	}
	groupsByteSize, err := getRealSizeOf(a.Groups)
	if err != nil {
		log.Printf("[authz] <WARN> Failed to get the size of the groups map: %s", err)
	}
	usersByteSize, err := getRealSizeOf(a.Users)
	if err != nil {
		log.Printf("[authz] <WARN> Failed to get the size of the users map: %s", err)
	}
	log.Printf(
		"[authz] <INFO> Metrics: %d roles (%d bytes), %d groups (%d bytes), %d users (%d bytes)",
		len(a.Roles), rolesByteSize,
		len(a.Groups), groupsByteSize,
		len(a.Users), usersByteSize,
	)
}

// save writes out the authorizer's data to the file sytem.
func (a *Authorizer) save(fname string) error {
	serialized, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("Failed to marshal authorizer as JSON: %s", err)
	}
	err = ioutil.WriteFile(fname, serialized, 0666) // perms: rw-rw-rw-
	if err != nil {
		return fmt.Errorf("Failed to write serialized authorizer to file system: %s", err)
	}
	return nil
}

func hasPermissionOnResource(entity string, m map[string]resourcePermissions, resource string, permission string) bool {
	resourcePerms, ok := m[entity]
	if !ok {
		return false
	}
	perms, ok := resourcePerms[resource]
	if !ok {
		return false
	}
	return perms.has(permission)
}

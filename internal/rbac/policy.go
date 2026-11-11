package rbac

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Built-in role names; generated roles are "<instance>.<db>.read" and "<instance>.<db>.write".
const (
	AdminRole  = "pg-admin"
	ReaderRole = "pg-reader"
)

// Policy is a checked set of roles and bindings, ready to answer access questions.
type Policy struct {
	roles    map[string]*Role
	bindings []*Binding
}

// Instances maps each configured instance to the databases pgauth serves on it.
type Instances map[string][]string

var generatedRole = regexp.MustCompile(`\.(read|write)$`)

// Compile adds the built-in roles and checks the resources as a whole: duplicate names, role
// references, and grants against instances. With nil instances it skips every instance check.
func Compile(res *Resources, instances Instances) (*Policy, Errors) {
	var errs Errors
	p := &Policy{roles: map[string]*Role{}}
	for _, r := range builtinRoles(instances) {
		p.roles[r.Name] = r
	}
	for _, r := range res.Roles {
		if prev, ok := p.roles[r.Name]; ok {
			if prev.Builtin {
				errs = append(errs, Error{r.Pos, fmt.Sprintf("PgRole %s has the name of a built-in role", r.Name)})
			} else {
				errs = append(errs, Error{r.Pos, fmt.Sprintf("duplicate PgRole %s, first defined at %s", r.Name, prev.Pos)})
			}
			continue
		}
		if r.Name != "" {
			p.roles[r.Name] = r
		}
		if instances == nil {
			continue
		}
		for _, g := range r.Grants {
			dbs, ok := instances[g.Instance]
			switch {
			case g.Instance == "":
			case !ok:
				errs = append(errs, Error{g.Pos, fmt.Sprintf("instance %s is not configured", g.Instance)})
			case g.Database != "*" && g.Database != "" && !slices.Contains(dbs, g.Database):
				errs = append(errs, Error{g.Pos, fmt.Sprintf("database %s/%s is not configured", g.Instance, g.Database)})
			}
		}
	}
	seen := map[string]*Binding{}
	for _, b := range res.Bindings {
		if prev, ok := seen[b.Name]; ok && b.Name != "" {
			errs = append(errs, Error{b.Pos, fmt.Sprintf("duplicate PgRoleBinding %s, first defined at %s", b.Name, prev.Pos)})
			continue
		}
		seen[b.Name] = b
		if b.RoleRef != "" && p.roles[b.RoleRef] == nil && (instances != nil || !generatedRole.MatchString(b.RoleRef)) {
			errs = append(errs, Error{b.RoleRefPos, fmt.Sprintf("roleRef %s names no PgRole", b.RoleRef)})
		}
		p.bindings = append(p.bindings, b)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return p, nil
}

func builtinRoles(instances Instances) []*Role {
	admin := &Role{Name: AdminRole, Builtin: true}
	reader := &Role{Name: ReaderRole, Builtin: true}
	out := []*Role{admin, reader}
	names := make([]string, 0, len(instances))
	for name := range instances {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, inst := range names {
		admin.Grants = append(admin.Grants, Grant{Instance: inst, Database: "*", Level: Write})
		reader.Grants = append(reader.Grants, Grant{Instance: inst, Database: "*", Level: Read})
		for _, db := range instances[inst] {
			for _, lv := range []Level{Read, Write} {
				out = append(out, &Role{
					Name:    fmt.Sprintf("%s.%s.%s", inst, db, lv),
					Grants:  []Grant{{Instance: inst, Database: db, Level: lv}},
					Builtin: true,
				})
			}
		}
	}
	return out
}

// Who is the holder a binding is matched against.
type Who struct {
	User   string
	Groups []string
	// FoldUser compares User subjects case-insensitively (Unicode simple case folding).
	FoldUser bool
}

// Access returns the highest level any binding of who grants on instance/db, and the names of the
// bindings that grant it.
func (p *Policy) Access(who Who, instance, db string) (Level, []string) {
	level := None
	var matched []string
	for _, b := range p.bindings {
		if !b.matches(who) {
			continue
		}
		role := p.roles[b.RoleRef]
		if role == nil {
			continue
		}
		granted := None
		for _, g := range role.Grants {
			if g.Instance == instance && (g.Database == "*" || g.Database == db) {
				granted = max(granted, g.Level)
			}
		}
		if granted > None {
			matched = append(matched, b.Name)
			level = max(level, granted)
		}
	}
	return level, matched
}

func (b *Binding) matches(who Who) bool {
	for _, s := range b.Subjects {
		switch {
		case s.Kind == "Group" && slices.Contains(who.Groups, s.Name):
			return true
		case s.Kind != "User" || who.User == "":
		case s.Name == who.User, who.FoldUser && strings.EqualFold(s.Name, who.User):
			return true
		}
	}
	return false
}

// Size reports the number of user-defined roles and bindings, for logs.
func (p *Policy) Size() (roles, bindings int) {
	for _, r := range p.roles {
		if !r.Builtin {
			roles++
		}
	}
	return roles, len(p.bindings)
}

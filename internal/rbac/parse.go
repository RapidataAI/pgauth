// Package rbac reads PgRole and PgRoleBinding resources and answers which access level a user has
// on a database. Parsing takes bytes, so a directory, a ConfigMap or a CRD watch can all feed it.
package rbac

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const APIVersion = "pgauth.dev/v1alpha1"

type Level int

const (
	None Level = iota
	Read
	Write
)

func (l Level) String() string {
	switch l {
	case Read:
		return "read"
	case Write:
		return "write"
	default:
		return "none"
	}
}

// Pos is where a value was written, for file:line messages.
type Pos struct {
	File string
	Line int
}

func (p Pos) String() string { return fmt.Sprintf("%s:%d", p.File, p.Line) }

type Grant struct {
	Instance string
	// Database "*" means every database of the instance.
	Database string
	Level    Level
	Pos      Pos
}

type Role struct {
	Name    string
	Grants  []Grant
	Builtin bool
	Pos     Pos
}

type Subject struct {
	Kind string // "User" or "Group"
	Name string
	Pos  Pos
}

type Binding struct {
	Name       string
	RoleRef    string
	RoleRefPos Pos
	Subjects   []Subject
	Pos        Pos
}

// File is one source document set, e.g. one *.yaml file.
type File struct {
	Name string
	Data []byte
}

type Error struct {
	Pos Pos
	Msg string
}

func (e Error) Error() string { return e.Pos.String() + ": " + e.Msg }

type Errors []Error

func (es Errors) Error() string {
	lines := make([]string, len(es))
	for i, e := range es {
		lines[i] = e.Error()
	}
	return strings.Join(lines, "\n")
}

// Resources are the parsed objects before they are checked against the instances.
type Resources struct {
	Roles    []*Role
	Bindings []*Binding
}

var namePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9._]*[a-z0-9])?$`)

// Parse decodes every document of every file and checks each object on its own: schema, unknown
// fields, required values. Cross-object checks happen in Compile.
func Parse(files []File) (*Resources, Errors) {
	res := &Resources{}
	var errs Errors
	for _, f := range files {
		dec := yaml.NewDecoder(bytes.NewReader(f.Data))
		for {
			var doc yaml.Node
			err := dec.Decode(&doc)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				errs = append(errs, Error{Pos{f.Name, yamlErrLine(err)}, err.Error()})
				break
			}
			if len(doc.Content) == 0 || doc.Content[0].Tag == "!!null" {
				continue
			}
			p := &parser{file: f.Name}
			p.object(doc.Content[0], res)
			errs = append(errs, p.errs...)
		}
	}
	return res, errs
}

type parser struct {
	file string
	errs Errors
}

func (p *parser) errorf(n *yaml.Node, format string, args ...any) {
	p.errs = append(p.errs, Error{Pos{p.file, n.Line}, fmt.Sprintf(format, args...)})
}

func (p *parser) pos(n *yaml.Node) Pos { return Pos{p.file, n.Line} }

// fields checks that n is a mapping with only the allowed keys and returns its values by key.
func (p *parser) fields(n *yaml.Node, path string, allowed ...string) map[string]*yaml.Node {
	if n.Kind != yaml.MappingNode {
		p.errorf(n, "%s must be a mapping", path)
		return nil
	}
	out := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if !slices.Contains(allowed, k.Value) {
			p.errorf(k, "unknown field %s.%s", path, k.Value)
			continue
		}
		out[k.Value] = v
	}
	return out
}

func (p *parser) str(m map[string]*yaml.Node, key, path string, parent *yaml.Node) string {
	v, ok := m[key]
	if !ok {
		p.errorf(parent, "%s.%s is required", path, key)
		return ""
	}
	if v.Kind != yaml.ScalarNode || v.Value == "" {
		p.errorf(v, "%s.%s must be a non-empty string", path, key)
		return ""
	}
	return v.Value
}

func (p *parser) list(m map[string]*yaml.Node, key, path string, parent *yaml.Node) []*yaml.Node {
	v, ok := m[key]
	if !ok {
		p.errorf(parent, "%s.%s is required", path, key)
		return nil
	}
	if v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
		p.errorf(v, "%s.%s must be a non-empty list", path, key)
		return nil
	}
	return v.Content
}

func (p *parser) object(n *yaml.Node, res *Resources) {
	top := p.fields(n, "object", "apiVersion", "kind", "metadata", "spec")
	if top == nil {
		return
	}
	if v := p.str(top, "apiVersion", "object", n); v != "" && v != APIVersion {
		p.errorf(top["apiVersion"], "apiVersion must be %s, got %s", APIVersion, v)
	}
	kind := p.str(top, "kind", "object", n)
	var name string
	if md, ok := top["metadata"]; ok {
		meta := p.fields(md, "metadata", "name", "labels", "annotations")
		if meta != nil {
			name = p.str(meta, "name", "metadata", md)
			if name != "" && !namePattern.MatchString(name) {
				p.errorf(meta["name"], "metadata.name %q must be lowercase letters, digits, '-', '.' or '_'", name)
			}
		}
	} else {
		p.errorf(n, "object.metadata is required")
	}
	spec, ok := top["spec"]
	if !ok {
		p.errorf(n, "object.spec is required")
		return
	}
	switch kind {
	case "PgRole":
		if r := p.role(spec, name); r != nil {
			r.Pos = p.pos(n)
			res.Roles = append(res.Roles, r)
		}
	case "PgRoleBinding":
		if b := p.binding(spec, name); b != nil {
			b.Pos = p.pos(n)
			res.Bindings = append(res.Bindings, b)
		}
	case "":
	default:
		p.errorf(top["kind"], "kind must be PgRole or PgRoleBinding, got %s", kind)
	}
}

func (p *parser) role(spec *yaml.Node, name string) *Role {
	m := p.fields(spec, "spec", "grants")
	if m == nil {
		return nil
	}
	r := &Role{Name: name}
	for _, g := range p.list(m, "grants", "spec", spec) {
		gm := p.fields(g, "spec.grants[]", "instance", "database", "level")
		if gm == nil {
			continue
		}
		grant := Grant{
			Instance: p.str(gm, "instance", "spec.grants[]", g),
			Database: p.str(gm, "database", "spec.grants[]", g),
			Pos:      p.pos(g),
		}
		switch lv := p.str(gm, "level", "spec.grants[]", g); lv {
		case "read":
			grant.Level = Read
		case "write":
			grant.Level = Write
		case "":
		default:
			p.errorf(gm["level"], "spec.grants[].level must be read or write, got %s", lv)
		}
		r.Grants = append(r.Grants, grant)
	}
	return r
}

func (p *parser) binding(spec *yaml.Node, name string) *Binding {
	m := p.fields(spec, "spec", "roleRef", "subjects")
	if m == nil {
		return nil
	}
	b := &Binding{Name: name}
	if ref, ok := m["roleRef"]; ok {
		rm := p.fields(ref, "spec.roleRef", "kind", "name")
		if rm != nil {
			if k := p.str(rm, "kind", "spec.roleRef", ref); k != "" && k != "PgRole" {
				p.errorf(rm["kind"], "spec.roleRef.kind must be PgRole, got %s", k)
			}
			b.RoleRef = p.str(rm, "name", "spec.roleRef", ref)
			b.RoleRefPos = p.pos(ref)
		}
	} else {
		p.errorf(spec, "spec.roleRef is required")
	}
	for _, s := range p.list(m, "subjects", "spec", spec) {
		sm := p.fields(s, "spec.subjects[]", "kind", "name")
		if sm == nil {
			continue
		}
		subj := Subject{Kind: p.str(sm, "kind", "spec.subjects[]", s), Name: p.str(sm, "name", "spec.subjects[]", s), Pos: p.pos(s)}
		if subj.Kind != "" && subj.Kind != "User" && subj.Kind != "Group" {
			p.errorf(sm["kind"], "spec.subjects[].kind must be User or Group, got %s", subj.Kind)
		}
		b.Subjects = append(b.Subjects, subj)
	}
	return b
}

// Warnings are findings that do not make the resources invalid. Uppercase User names are flagged
// only when users are compared exactly (foldUsers false).
func (res *Resources) Warnings(foldUsers bool) Errors {
	var out Errors
	if foldUsers {
		return nil
	}
	for _, b := range res.Bindings {
		for _, s := range b.Subjects {
			if s.Kind == "User" && s.Name != strings.ToLower(s.Name) {
				out = append(out, Error{s.Pos, fmt.Sprintf("warning: User %s has uppercase letters; oidc.usernameCaseInsensitive is false, so it matches only that exact casing", s.Name)})
			}
		}
	}
	return out
}

var lineInErr = regexp.MustCompile(`line (\d+)`)

func yamlErrLine(err error) int {
	var n int
	if m := lineInErr.FindStringSubmatch(err.Error()); m != nil {
		fmt.Sscanf(m[1], "%d", &n)
	}
	return n
}

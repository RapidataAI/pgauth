package rbac

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var instances = Instances{"cloudsql-main": {"order", "assignment"}}

const header = "apiVersion: pgauth.dev/v1alpha1\n"

func TestLint(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		instances Instances
		want      []string // each a substring of one error, in order; empty = valid
	}{
		{"valid role, bindings to built-in and generated roles", header + `kind: PgRole
metadata: {name: analyst}
spec:
  grants:
    - {instance: cloudsql-main, database: "*", level: read}
---
` + header + `kind: PgRoleBinding
metadata: {name: analysts}
spec:
  roleRef: {kind: PgRole, name: analyst}
  subjects: [{kind: Group, name: analysts}]
---
` + header + `kind: PgRoleBinding
metadata: {name: admins}
spec:
  roleRef: {kind: PgRole, name: pg-admin}
  subjects: [{kind: Group, name: postgres-admins}, {kind: User, name: mari@example.com}]
---
` + header + `kind: PgRoleBinding
metadata: {name: mari-order}
spec:
  roleRef: {kind: PgRole, name: cloudsql-main.order.read}
  subjects: [{kind: User, name: mari@example.com}]
`, instances, nil},
		{"unknown field", header + `kind: PgRoleBinding
metadata: {name: x}
spec:
  roleRef: {kind: PgRole, name: pg-admin}
  subject: [{kind: User, name: a}]
`, instances, []string{"a.yaml:6: unknown field spec.subject", "a.yaml:5: spec.subjects is required"}},
		{"wrong apiVersion and kind", `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: x}
spec: {}
`, instances, []string{"a.yaml:1: apiVersion must be pgauth.dev/v1alpha1", "a.yaml:2: kind must be PgRole or PgRoleBinding"}},
		{"duplicate binding", header + `kind: PgRoleBinding
metadata: {name: x}
spec: {roleRef: {kind: PgRole, name: pg-admin}, subjects: [{kind: User, name: a}]}
---
` + header + `kind: PgRoleBinding
metadata: {name: x}
spec: {roleRef: {kind: PgRole, name: pg-reader}, subjects: [{kind: User, name: b}]}
`, instances, []string{"a.yaml:6: duplicate PgRoleBinding x, first defined at a.yaml:1"}},
		{"role with a built-in name", header + `kind: PgRole
metadata: {name: cloudsql-main.order.read}
spec: {grants: [{instance: cloudsql-main, database: order, level: write}]}
`, instances, []string{"a.yaml:1: PgRole cloudsql-main.order.read has the name of a built-in role"}},
		{"roleRef to a missing role", header + `kind: PgRoleBinding
metadata: {name: x}
spec:
  roleRef: {kind: PgRole, name: cloudsql-main.billing.read}
  subjects: [{kind: User, name: a}]
`, instances, []string{"a.yaml:5: roleRef cloudsql-main.billing.read names no PgRole"}},
		{"grants outside the config", header + `kind: PgRole
metadata: {name: x}
spec:
  grants:
    - {instance: bidder, database: bids, level: read}
    - {instance: cloudsql-main, database: billing, level: read}
`, instances, []string{"a.yaml:6: instance bidder is not configured", "a.yaml:7: database cloudsql-main/billing is not configured"}},
		{"bad subject kind and level", header + `kind: PgRole
metadata: {name: x}
spec: {grants: [{instance: cloudsql-main, database: order, level: admin}]}
---
` + header + `kind: PgRoleBinding
metadata: {name: y}
spec:
  roleRef: {kind: PgRole, name: x}
  subjects:
    - {kind: ServiceAccount, name: a}
`, instances, []string{"a.yaml:4: spec.grants[].level must be read or write", "a.yaml:12: spec.subjects[].kind must be User or Group"}},
		{"broken YAML", header + "kind: PgRole\nmetadata: {name: x\n", instances, []string{"a.yaml:2: yaml: line 2:"}},
		{"without a config, instances and generated roles are not checked", header + `kind: PgRole
metadata: {name: x}
spec: {grants: [{instance: bidder, database: bids, level: read}]}
---
` + header + `kind: PgRoleBinding
metadata: {name: y}
spec: {roleRef: {kind: PgRole, name: bidder.bids.write}, subjects: [{kind: User, name: a}]}
`, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load([]File{{Name: "a.yaml", Data: []byte(tt.yaml)}}, tt.instances)
			var got []string
			if err != nil {
				got = strings.Split(err.Error(), "\n")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("errors:\n%s\nwant %d matching %q", strings.Join(got, "\n"), len(tt.want), tt.want)
			}
			for i := range got {
				if !strings.Contains(got[i], tt.want[i]) {
					t.Errorf("error %d = %q, want it to contain %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLastValidWins(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(dir, "bindings.yaml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bindTo := func(role string) string {
		return header + "kind: PgRoleBinding\nmetadata: {name: mari}\nspec:\n  roleRef: {kind: PgRole, name: " + role +
			"}\n  subjects: [{kind: User, name: mari@example.com}]\n"
	}
	level := func(s *Store) Level {
		if s.Policy() == nil {
			return None
		}
		l, _ := s.Policy().Access("mari@example.com", nil, "cloudsql-main", "order")
		return l
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	store := NewStore(instances, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	write(bindTo("cloudsql-main.order.missing"))
	go store.WatchDir(ctx, dir, 20*time.Millisecond)
	waitFor("the first invalid set to be rejected", func() bool { return store.Status().Rejected != nil })
	if store.Status().Loaded || store.Policy() != nil {
		t.Fatal("an invalid first set must leave pgauth without rules")
	}

	write(bindTo("cloudsql-main.order.read"))
	waitFor("the valid set to load", func() bool { return store.Status().Loaded && store.Status().Rejected == nil })
	if level(store) != Read {
		t.Fatalf("level = %v, want read", level(store))
	}

	write(bindTo("pg-admin") + "  extra: field\n")
	waitFor("the bad change to be rejected", func() bool { return store.Status().Rejected != nil })
	if !store.Status().Loaded || level(store) != Read {
		t.Fatalf("after a rejected change: loaded %v, level %v; want the previous set (read) still live", store.Status().Loaded, level(store))
	}

	write(bindTo("pg-admin"))
	waitFor("the fixed set to load", func() bool { return store.Status().Rejected == nil })
	if level(store) != Write {
		t.Fatalf("level = %v, want write", level(store))
	}
}

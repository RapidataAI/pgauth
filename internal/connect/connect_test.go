package connect

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RapidataAI/pgauth/internal/api"
)

func TestTargetDatabase(t *testing.T) {
	tests := []struct{ instance, db, want string }{
		{"cloudsql-main", "order", "cloudsql-main/order"},
		{"cloudsql-main", "cloudsql-main/order", "cloudsql-main/order"},
		{"cloudsql-main", "bidder/bids", "bidder/bids"},
		{"cloudsql-main", "", ""},
		{"", "order", "order"},
		{"", "cloudsql-main/order", "cloudsql-main/order"},
	}
	for _, tt := range tests {
		if got := TargetDatabase(tt.instance, tt.db); got != tt.want {
			t.Errorf("TargetDatabase(%q, %q) = %q, want %q", tt.instance, tt.db, got, tt.want)
		}
	}
}

func TestResolve(t *testing.T) {
	disc := &api.Discovery{Instances: []api.Instance{
		{Name: "main", Databases: []string{"order", "assignment", "audit"}},
		{Name: "bidder", Databases: []string{"bids", "audit"}},
	}}
	envs := []*Env{{Name: "prod", disc: disc, discAt: time.Now()}, {Name: "test", disc: disc, discAt: time.Now()}}
	r := NewRouter(envs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tests := []struct {
		database, env, forward, err string
	}{
		{"prod/order", "prod", "main/order", ""},
		{"test/bids", "test", "bidder/bids", ""},
		{"prod/bidder/audit", "prod", "bidder/audit", ""},
		{"prod/main/missing", "prod", "main/missing", ""},
		{"prod/audit", "", "", "prod/audit is on several instances; use prod/main/audit or prod/bidder/audit"},
		{"prod/payment", "", "", "prod serves no database payment; `pgauth ls prod` lists what you can reach"},
		{"order", "", "", "use <env>/<db>; environments: prod, test"},
		{"main/order", "", "", "use <env>/<db>; environments: prod, test"},
		{"prod/a/b/c", "", "", "use <env>/<db>; environments: prod, test"},
	}
	for _, tt := range tests {
		e, forward, err := r.Resolve(context.Background(), tt.database)
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("%s: err = %v, want %q", tt.database, err, tt.err)
			}
			continue
		}
		if err != nil || e.Name != tt.env || forward != tt.forward {
			t.Errorf("%s: got %v %q %v, want %s %s", tt.database, e, forward, err, tt.env, tt.forward)
		}
	}
	if got := envs[0].Address(disc, "main", "order"); got != "prod/order" {
		t.Errorf("address of a unique database = %s", got)
	}
	if got := envs[0].Address(disc, "bidder", "audit"); got != "prod/bidder/audit" {
		t.Errorf("address of a shared database name = %s", got)
	}
}

func jwtExpiring(exp time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig"
}

// TestFileSource walks one source through a token file that appears, expires and is fixed, without
// a restart: each row changes the files, then asks for a token.
func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	tokenPath, statusPath := filepath.Join(dir, "token.json"), filepath.Join(dir, "status")
	fresh, stale := jwtExpiring(time.Now().Add(time.Hour)), jwtExpiring(time.Now().Add(-time.Minute))
	src := &FileSource{Path: tokenPath, Field: "access_token", StatusFile: statusPath}
	raw := &FileSource{Path: filepath.Join(dir, "raw.jwt")}
	tests := []struct {
		name          string
		src           *FileSource
		token, status *string // nil leaves the file as is; "" deletes it
		want, err     string
	}{
		{"missing, no status file", src, ptr(""), ptr(""), "", "token file " + tokenPath + " missing or expired"},
		{"missing, status explains", src, nil, ptr("connect Rapidata in Settings\n"), "", "connect Rapidata in Settings"},
		{"expired", src, ptr(`{"access_token":"` + stale + `"}`), ptr(""), "", "token file " + tokenPath + " missing or expired"},
		{"unparsable", src, ptr(`{"access_token":`), nil, "", "token file " + tokenPath + " missing or expired"},
		{"fixed, read again", src, ptr(`{"access_token":"` + fresh + `"}`), nil, fresh, ""},
		{"raw JWT file", raw, nil, nil, "", "token file " + raw.Path + " missing or expired"},
	}
	for _, tt := range tests {
		for path, content := range map[string]*string{tokenPath: tt.token, statusPath: tt.status} {
			switch {
			case content == nil:
			case *content == "":
				_ = os.Remove(path)
			default:
				if err := os.WriteFile(path, []byte(*content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		got, err := tt.src.Token(context.Background())
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("%s: err = %v, want %q", tt.name, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: token %q, err %v", tt.name, got, err)
		}
	}
	if err := os.WriteFile(raw.Path, []byte(fresh+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := raw.Token(context.Background()); err != nil || got != fresh {
		t.Errorf("raw JWT: %q, %v", got, err)
	}
}

func ptr(s string) *string { return &s }

func TestAddEnv(t *testing.T) {
	disc := func(issuer string) *api.Discovery {
		return &api.Discovery{
			Postgres: "pgauth.example.com:5432", Issuer: issuer, Audience: "https://postgres.example.com", CLIClientID: "pgauth-cli",
			Scopes: api.Scopes{Read: "postgres:read", Write: "postgres:write"},
		}
	}
	tests := []struct {
		name      string
		existing  *EnvConfig
		issuer    string
		opts      AddOptions
		wantScope string
		err       string
	}{
		{"new environment, read", nil, "https://auth.example.com/", AddOptions{}, "openid offline_access postgres:read", ""},
		{"new environment, write", nil, "https://auth.example.com/", AddOptions{Write: true}, "openid offline_access postgres:write", ""},
		{"same issuer updates", &EnvConfig{Server: "old:5432", Token: TokenConfig{Login: "browser", Issuer: "https://auth.example.com/", ClientID: "x"}},
			"https://auth.example.com/", AddOptions{}, "openid offline_access postgres:read", ""},
		{"changed issuer is refused", &EnvConfig{Server: "old:5432", Token: TokenConfig{Login: "browser", Issuer: "https://auth.example.com/", ClientID: "x"}},
			"https://evil.example.com/", AddOptions{}, "", "pinned to issuer https://auth.example.com/"},
		{"changed issuer with --force", &EnvConfig{Server: "old:5432", Token: TokenConfig{Login: "browser", Issuer: "https://auth.example.com/", ClientID: "x"}},
			"https://new.example.com/", AddOptions{Force: true}, "openid offline_access postgres:read", ""},
		{"file token is not replaced", &EnvConfig{Server: "old:5432", Token: TokenConfig{File: "/run/token.json"}},
			"https://auth.example.com/", AddOptions{}, "", "reads its token from /run/token.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{Environments: map[string]*EnvConfig{}}
			if tt.existing != nil {
				f.Environments["prod"] = tt.existing
			}
			err := AddEnv(f, "prod", "https://pgauth.example.com:8443", disc(tt.issuer), tt.opts)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				if f.Environments["prod"] != tt.existing {
					t.Fatal("a refused add changed the environment")
				}
				return
			}
			e := f.Environments["prod"]
			if err != nil || e.Server != "pgauth.example.com:5432" || e.Token.Issuer != tt.issuer || e.Token.ClientID != "pgauth-cli" ||
				e.Token.Resource != "https://postgres.example.com" || e.Token.Scope != tt.wantScope || e.Token.Login != "browser" {
				t.Fatalf("err %v, env %+v", err, e)
			}
			if err := f.Validate(); err != nil {
				t.Fatalf("written config does not validate: %v", err)
			}
		})
	}
}

func TestLegacy(t *testing.T) {
	tests := []struct {
		f    File
		want bool
	}{
		{File{Server: "pgauth.example.com:5432", Issuer: "https://auth.example.com/"}, true},
		{File{Listeners: []Listener{{Listen: "127.0.0.1:15432", Instance: "main"}}}, true},
		{File{Environments: map[string]*EnvConfig{"prod": {Server: "p:5432"}}}, false},
		{File{}, false},
	}
	for i, tt := range tests {
		if got := tt.f.Legacy(); got != tt.want {
			t.Errorf("row %d: Legacy() = %v, want %v", i, got, tt.want)
		}
	}
}

func TestExampleConfigsValidate(t *testing.T) {
	for _, path := range []string{"../../connect.example.yaml", "../../examples/rapidata-test/connect.yaml"} {
		f, err := LoadFile(path)
		if err == nil {
			err = f.Validate()
		}
		if err != nil || f.Legacy() {
			t.Errorf("%s: %v (legacy %v)", path, err, f.Legacy())
		}
	}
}

package connect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
		port                        string // "" is the main listener, else the env a listener is bound to
		database, env, forward, err string
	}{
		{"", "prod/order", "prod", "main/order", ""},
		{"", "test/bids", "test", "bidder/bids", ""},
		{"", "prod/bidder/audit", "prod", "bidder/audit", ""},
		{"", "prod/main/missing", "prod", "main/missing", ""},
		{"", "prod/audit", "", "", "prod/audit is on several instances; use prod/main/audit or prod/bidder/audit"},
		{"", "prod/payment", "", "", "prod serves no database payment; `pgauth ls prod` lists what you can reach"},
		{"", "order", "", "", "use <env>/<db>; environments: prod, test"},
		{"", "main/order", "", "", "use <env>/<db>; environments: prod, test"},
		{"", "prod/a/b/c", "", "", "use <env>/<db>; environments: prod, test"},
		{"prod", "order", "prod", "main/order", ""},
		{"prod", "bidder/audit", "prod", "bidder/audit", ""},
		{"prod", "prod/order", "prod", "main/order", ""},
		{"prod", "audit", "", "", "audit is on several instances; use prod/main/audit or prod/bidder/audit"},
		{"prod", "test/order", "", "", "this port serves prod; test/order names test, use its port or the main one"},
		{"prod", "a/b/c", "", "", "this port serves prod; use <db> or <instance>/<db>"},
	}
	for _, tt := range tests {
		resolve := r.Resolve
		if tt.port != "" {
			resolve = func(ctx context.Context, db string) (*Env, string, error) { return r.ResolveOn(ctx, tt.port, db) }
		}
		e, forward, err := resolve(context.Background(), tt.database)
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Errorf("[%s] %s: err = %v, want %q", tt.port, tt.database, err, tt.err)
			}
			continue
		}
		if err != nil || e.Name != tt.env || forward != tt.forward {
			t.Errorf("[%s] %s: got %v %q %v, want %s %s", tt.port, tt.database, e, forward, err, tt.env, tt.forward)
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
		{"--ide-port adds a listener", nil, "https://auth.example.com/", AddOptions{IDEPort: 15432}, "openid offline_access postgres:read", ""},
		{"--ide-port taken by another env", nil, "https://auth.example.com/", AddOptions{IDEPort: 15433}, "", "port 15433 already serves environment test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{
				Environments: map[string]*EnvConfig{"test": {Server: "t:5432", Token: TokenConfig{File: "/t"}}},
				Listeners:    []Listener{{Listen: "127.0.0.1:15433", Env: "test"}},
			}
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
			wantListeners := 1
			if tt.opts.IDEPort != 0 {
				wantListeners = 2
				if l := f.Listeners[1]; l.Env != "prod" || l.Listen != "127.0.0.1:15432" {
					t.Fatalf("listener = %+v", l)
				}
			}
			if len(f.Listeners) != wantListeners {
				t.Fatalf("listeners = %+v", f.Listeners)
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

// TestDiscoveryFallback walks one environment through an API that answers, goes away and hangs;
// each row starts a fresh Env, as a restarted connector would, unless it keeps the last one.
func TestDiscoveryFallback(t *testing.T) {
	disc := api.Discovery{Instances: []api.Instance{{Name: "main", Databases: []string{"order"}}}}
	var mode atomic.Value // "up", "down" or "hang"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case "down":
			http.Error(w, "down", http.StatusServiceUnavailable)
		case "hang":
			<-r.Context().Done()
		default:
			_ = json.NewEncoder(w).Encode(disc)
		}
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "discovery-test.json")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	newRouter := func(cacheFile string) *Router {
		return NewRouter([]*Env{{Name: "test", API: srv.URL, HTTP: srv.Client(), CacheFile: cacheFile, LookupTimeout: 300 * time.Millisecond}}, log)
	}
	tests := []struct {
		name, mode, cacheFile, database string
		want, err                       string
		maxTime                         time.Duration
	}{
		{"api up resolves and caches", "up", cache, "test/order", "main/order", "", 0},
		{"api down, cached answer from disk", "down", cache, "test/order", "main/order", "", 0},
		{"api down, no cache", "down", "", "test/order", "",
			"pgauth api " + srv.URL + " unreachable (503 Service Unavailable); use test/<instance>/order to connect without it", 0},
		{"api hangs, short timeout", "hang", "", "test/order", "",
			"pgauth api " + srv.URL + " unreachable (timeout); use test/<instance>/order to connect without it", 2 * time.Second},
		{"instance-qualified needs no api", "hang", "", "test/main/order", "main/order", "", 100 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode.Store(tt.mode)
			start := time.Now()
			_, got, err := newRouter(tt.cacheFile).Resolve(context.Background(), tt.database)
			if tt.maxTime > 0 && time.Since(start) > tt.maxTime {
				t.Errorf("took %s, want under %s", time.Since(start), tt.maxTime)
			}
			if tt.err != "" {
				if err == nil || err.Error() != tt.err {
					t.Fatalf("err = %v\nwant  %s", err, tt.err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %s", got, err, tt.want)
			}
		})
	}
	if lookupTimeout != 3*time.Second {
		t.Errorf("default lookup timeout = %s, want 3s", lookupTimeout)
	}
}

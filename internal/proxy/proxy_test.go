package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/RapidataAI/pgauth/internal/api"
	"github.com/RapidataAI/pgauth/internal/config"
	pgconnect "github.com/RapidataAI/pgauth/internal/connect"
	"github.com/RapidataAI/pgauth/internal/rbac"
	"github.com/RapidataAI/pgauth/internal/roles"
	"github.com/RapidataAI/pgauth/internal/telemetry"
	"github.com/RapidataAI/pgauth/internal/token"
)

const (
	instanceName = "cloudsql-main"
	audience     = "https://postgres.example.test"
	defaultUser  = "mari@example.com"
)

// setupSQL prepares an instance with the README's required steps only, without the optional hardening.
var setupSQL = []string{
	`CREATE ROLE pgauth_temp NOLOGIN`,
	`CREATE ROLE pgauth LOGIN PASSWORD 'issuer-secret' CREATEROLE`,
	`GRANT pg_signal_backend TO pgauth`,
	`GRANT pgauth_temp TO pgauth WITH ADMIN OPTION`,
	`CREATE ROLE pgauth_stats NOLOGIN`,
	`GRANT pgauth_stats TO pgauth WITH ADMIN OPTION`,
}

func setupDatabaseSQL(db string) []string {
	return []string{
		fmt.Sprintf(`CREATE DATABASE %q`, db),
		fmt.Sprintf(`CREATE ROLE %s_service LOGIN`, db),
		fmt.Sprintf(`CREATE ROLE %s_read NOLOGIN`, db),
		fmt.Sprintf(`CREATE ROLE %s_write NOLOGIN`, db),
		fmt.Sprintf(`GRANT %s_read, %s_write TO pgauth WITH ADMIN OPTION`, db, db),
	}
}

func setupInDatabaseSQL(db string) []string {
	return []string{
		fmt.Sprintf(`GRANT USAGE, CREATE ON SCHEMA public TO %s_service`, db),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s_read, %s_write`, db, db),
		fmt.Sprintf(`ALTER DEFAULT PRIVILEGES FOR ROLE %s_service IN SCHEMA public GRANT SELECT ON TABLES TO %s_read`, db, db),
		fmt.Sprintf(`ALTER DEFAULT PRIVILEGES FOR ROLE %s_service IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s_write`, db, db),
		fmt.Sprintf(`SET ROLE %s_service`, db),
		`CREATE TABLE items (id int)`,
		`INSERT INTO items VALUES (1)`,
		`RESET ROLE`,
	}
}

type env struct {
	adminDSN string
	host     string
	port     int
	issuer   *issuer
	certFile string
	keyFile  string
	credFile string
}

var shared *env

func TestMain(m *testing.M) {
	ctx := context.Background()
	otel.SetTracerProvider(sdktrace.NewTracerProvider())
	pg, err := tcpostgres.Run(ctx, "postgres:18",
		tcpostgres.WithUsername("postgres"), tcpostgres.WithPassword("postgres"), tcpostgres.BasicWaitStrategies())
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		os.Exit(1)
	}
	code := func() int {
		defer testcontainers.TerminateContainer(pg)
		e, err := newEnv(ctx, pg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "setup:", err)
			return 1
		}
		defer e.issuer.srv.Close()
		shared = e
		return m.Run()
	}()
	os.Exit(code)
}

func newEnv(ctx context.Context, pg *tcpostgres.PostgresContainer) (*env, error) {
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, err
	}
	host, err := pg.Host(ctx)
	if err != nil {
		return nil, err
	}
	port, err := pg.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, err
	}
	stmts := setupSQL
	for _, db := range []string{"order", "assignment"} {
		stmts = append(stmts, setupDatabaseSQL(db)...)
	}
	if err := execAll(ctx, dsn, stmts); err != nil {
		return nil, err
	}
	for _, db := range []string{"order", "assignment"} {
		if err := execAll(ctx, strings.Replace(dsn, "/postgres?", "/"+db+"?", 1), setupInDatabaseSQL(db)); err != nil {
			return nil, err
		}
	}
	dir, err := os.MkdirTemp("", "pgauth-test")
	if err != nil {
		return nil, err
	}
	e := &env{adminDSN: dsn, host: host, port: int(port.Num()), issuer: newIssuer()}
	e.certFile, e.keyFile, err = writeCert(dir)
	if err != nil {
		return nil, err
	}
	e.credFile = filepath.Join(dir, "credentials.json")
	return e, os.WriteFile(e.credFile, []byte(`{"username":"pgauth","password":"issuer-secret"}`), 0o600)
}

func execAll(ctx context.Context, dsn string, stmts []string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}

// adminBinding gives the default user write on every database.
const adminBinding = `
apiVersion: pgauth.dev/v1alpha1
kind: PgRoleBinding
metadata: {name: default-admin}
spec:
  roleRef: {kind: PgRole, name: pg-admin}
  subjects: [{kind: User, name: mari@example.com}]
`

// startServer runs a pgauth with adminBinding against the shared Postgres; the returned store
// swaps the access rules.
// startServer also serves the HTTPS API (discovery, access) and returns its base URL.
func startServer(t *testing.T, mutate func(*config.Config)) (string, *rbac.Store, *auditLog, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		TLS: config.TLS{CertFile: shared.certFile, KeyFile: shared.keyFile},
		OIDC: config.OIDC{
			Issuer: shared.issuer.srv.URL, Audience: audience,
			AllowedClients: []string{"poseidon-session", "pgauth-cli"},
		},
		AccessHelp: "Ask in #data-access for a binding.",
		RBAC:       config.RBAC{Dir: "unused-in-tests"},
		Instances: []config.Instance{{
			Name: instanceName, Host: shared.host, Port: shared.port, SSLMode: "disable",
			Databases: []string{"order", "assignment"}, CredentialsFile: shared.credFile,
		}},
	}
	if mutate != nil {
		mutate(cfg)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	audit := &auditLog{}
	log := telemetry.Logger(audit, sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(audit))))
	verifier := token.NewVerifier(cfg.OIDC)
	go verifier.Start(ctx, log)
	cert, err := tls.LoadX509KeyPair(shared.certFile, shared.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	store := rbac.NewStore(cfg.Databases(), log)
	if err := store.Update([]rbac.File{{Name: "admin.yaml", Data: []byte(adminBinding)}}); err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, verifier, store, &tls.Config{Certificates: []tls.Certificate{cert}}, log)
	srv.Start(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for srv.Ready(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatalf("not ready: %v", srv.Ready(ctx))
		}
		time.Sleep(20 * time.Millisecond)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	apiSrv := httptest.NewUnstartedServer(api.New(cfg, verifier, store).Handler())
	apiSrv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	apiSrv.StartTLS()
	t.Cleanup(apiSrv.Close)
	return ln.Addr().String(), store, audit, apiSrv
}

// auditLog keeps the server's JSON log lines so tests can read the connect record.
// auditLog keeps the connect records twice: as stdout JSON lines and as OpenTelemetry log records,
// the two outputs of telemetry.Logger.
type auditLog struct {
	mu    sync.Mutex
	lines []map[string]any
	otel  []map[string]any
}

func (l *auditLog) Export(_ context.Context, records []sdklog.Record) error {
	for _, r := range records {
		if r.Body().Emit() != "connect" {
			continue
		}
		rec := map[string]any{"trace_id": r.TraceID()}
		r.WalkAttributes(func(kv attribute.KeyValue) bool {
			switch kv.Value.Type() {
			case attribute.STRINGSLICE:
				rec[string(kv.Key)] = strings.Join(kv.Value.AsStringSlice(), ",")
			case attribute.SLICE:
				var items []string
				for _, v := range kv.Value.AsSlice() {
					items = append(items, v.Emit())
				}
				rec[string(kv.Key)] = strings.Join(items, ",")
			default:
				rec[string(kv.Key)] = kv.Value.Emit()
			}
			return true
		})
		l.mu.Lock()
		l.otel = append(l.otel, rec)
		l.mu.Unlock()
	}
	return nil
}

func (l *auditLog) Shutdown(context.Context) error   { return nil }
func (l *auditLog) ForceFlush(context.Context) error { return nil }

func (l *auditLog) Write(p []byte) (int, error) {
	var line map[string]any
	if json.Unmarshal(p, &line) == nil && line["msg"] == "connect" {
		l.mu.Lock()
		l.lines = append(l.lines, line)
		l.mu.Unlock()
	}
	return len(p), nil
}

func (l *auditLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.lines)
}

// after waits for the connect record past index n in both outputs; it is written just after the
// client is greeted.
func (l *auditLog) after(t *testing.T, n int) (jsonLine, otelRecord map[string]any) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		l.mu.Lock()
		if len(l.lines) > n && len(l.otel) > n {
			jsonLine, otelRecord = l.lines[n], l.otel[n]
			l.mu.Unlock()
			return jsonLine, otelRecord
		}
		l.mu.Unlock()
	}
	t.Fatal("no connect log record")
	return nil, nil
}

type claims struct {
	user     string // default defaultUser
	groups   []string
	group    string // sent as a plain string claim instead of groups, as IdPs do for one value
	scope    string // default "postgres:read"
	client   string
	audience string
	expired  bool
}

func connect(ctx context.Context, addr, db string, c claims) (*pgx.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%s user=anyone dbname=%s sslmode=require", host, port, db))
	if err != nil {
		return nil, err
	}
	cfg.Password = shared.issuer.token(c)
	return pgx.ConnectConfig(ctx, cfg)
}

func binding(name, role string, subjects ...string) string {
	return fmt.Sprintf("---\napiVersion: pgauth.dev/v1alpha1\nkind: PgRoleBinding\nmetadata: {name: %s}\nspec:\n  roleRef: {kind: PgRole, name: %s}\n  subjects: [%s]\n",
		name, role, strings.Join(subjects, ", "))
}

func user(name string) string  { return "{kind: User, name: " + name + "}" }
func group(name string) string { return "{kind: Group, name: " + name + "}" }

const analystRole = `
apiVersion: pgauth.dev/v1alpha1
kind: PgRole
metadata: {name: analyst}
spec:
  grants:
    - {instance: cloudsql-main, database: "*", level: read}
`

func TestConnect(t *testing.T) {
	addr, store, audit, _ := startServer(t, nil)
	var (
		mariOrderRead  = binding("mari-order", "cloudsql-main.order.read", user(defaultUser))
		mariOrderWrite = binding("mari-order", "cloudsql-main.order.write", user(defaultUser))
		admins         = binding("admins", "pg-admin", group("postgres-admins"))
		readers        = binding("readers", "pg-reader", group("postgres-admins"))
		analysts       = analystRole + binding("analysts", "analyst", group("analysts"))
		admin          = []string{"postgres-admins"}
	)
	tests := []struct {
		name        string
		claims      claims
		bindings    string
		db          string
		stmt        string
		wantConnect bool
		wantStmt    bool
		wantAudit   string // "granted/level/scope_cap" from the connect record, when set
	}{
		{"user binding reads", claims{}, mariOrderRead, "cloudsql-main/order", "SELECT count(*) FROM items", true, true, ""},
		{"read binding cannot insert", claims{scope: "postgres:write"}, mariOrderRead, "cloudsql-main/order", "INSERT INTO items VALUES (2)", true, false, ""},
		{"read binding cannot switch to the write group", claims{}, mariOrderRead, "cloudsql-main/order", "SET ROLE order_write", true, false, ""},
		{"binding on one database does not open another", claims{}, mariOrderRead, "cloudsql-main/assignment", "", false, false, ""},
		{"user names match case-insensitively", claims{user: "MARI@Example.com"}, mariOrderRead, "cloudsql-main/order", "SELECT 1", true, true, ""},
		{"groups claim as a single string", claims{user: "ada@example.com", group: "postgres-admins", scope: "postgres:write"}, admins, "cloudsql-main/order", "UPDATE items SET id = id", true, true, ""},
		{"single-string group must match whole", claims{user: "ada@example.com", group: "postgres-admins interns"}, admins, "cloudsql-main/order", "", false, false, ""},
		{"write binding with write scope updates", claims{scope: "postgres:write"}, mariOrderWrite, "cloudsql-main/order", "UPDATE items SET id = id", true, true, ""},
		{"write binding still reads", claims{scope: "postgres:write"}, mariOrderWrite, "cloudsql-main/order", "SELECT count(*) FROM items", true, true, ""},
		{"group pg-admin inserts with write scope", claims{user: "ada@example.com", groups: admin, scope: "postgres:write"}, admins, "cloudsql-main/assignment", "INSERT INTO items VALUES (3)", true, true, "write/write/write"},
		{"read scope caps pg-admin at read", claims{user: "ada@example.com", groups: admin, scope: "openid postgres:read"}, admins, "cloudsql-main/order", "INSERT INTO items VALUES (4)", true, false, "write/read/read"},
		{"no postgres scope is refused", claims{user: "ada@example.com", groups: admin, scope: "openid"}, admins, "cloudsql-main/order", "", false, false, "write/none/none"},
		{"pg-admin cannot create tables", claims{groups: admin, scope: "postgres:write"}, admins, "cloudsql-main/order", "CREATE TABLE t (id int)", true, false, ""},
		{"pg-admin cannot drop tables", claims{groups: admin, scope: "postgres:write"}, admins, "cloudsql-main/order", "DROP TABLE items", true, false, ""},
		{"pg-reader with write scope stays read", claims{groups: admin, scope: "postgres:write"}, readers, "cloudsql-main/order", "DELETE FROM items", true, false, ""},
		{"union of bindings takes the highest level", claims{groups: admin, scope: "postgres:write"}, readers + mariOrderWrite, "cloudsql-main/order", "UPDATE items SET id = id", true, true, ""},
		{"custom role with database * reads every database", claims{user: "bo@example.com", groups: []string{"analysts"}}, analysts, "cloudsql-main/assignment", "SELECT count(*) FROM items", true, true, ""},
		{"other group matches nothing", claims{user: "bo@example.com", groups: []string{"interns"}}, admins + analysts, "cloudsql-main/order", "", false, false, ""},
		{"pgauth-cli client is allowed", claims{client: "pgauth-cli"}, mariOrderRead, "cloudsql-main/order", "SELECT 1", true, true, ""},
		{"client outside the allowlist", claims{client: "other-app"}, mariOrderRead, "cloudsql-main/order", "", false, false, ""},
		{"expired token", claims{expired: true}, mariOrderRead, "cloudsql-main/order", "", false, false, ""},
		{"token for another audience", claims{audience: "https://api.example.test"}, mariOrderRead, "cloudsql-main/order", "", false, false, ""},
		{"unknown instance", claims{groups: admin}, admins, "other/order", "", false, false, ""},
		{"database not served", claims{groups: admin}, admins, "cloudsql-main/postgres", "", false, false, ""},
		{"database without instance", claims{groups: admin}, admins, "order", "", false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if err := store.Update([]rbac.File{{Name: "row.yaml", Data: []byte(tt.bindings)}}); err != nil {
				t.Fatalf("bindings: %v", err)
			}
			logged := audit.count()
			conn, err := connect(ctx, addr, tt.db, tt.claims)
			if (err == nil) != tt.wantConnect {
				t.Fatalf("connect error = %v, want connect %v", err, tt.wantConnect)
			}
			if tt.wantAudit != "" {
				j, o := audit.after(t, logged)
				if got := fmt.Sprintf("%v/%v/%v", j["granted"], j["level"], j["scope_cap"]); got != tt.wantAudit {
					t.Errorf("JSON granted/level/scope_cap = %s, want %s", got, tt.wantAudit)
				}
				if got := fmt.Sprintf("%v/%v/%v", o["granted"], o["level"], o["scope_cap"]); got != tt.wantAudit {
					t.Errorf("OTel granted/level/scope_cap = %s, want %s", got, tt.wantAudit)
				}
				var bindings []string
				for _, b := range j["bindings"].([]any) {
					bindings = append(bindings, b.(string))
				}
				for _, k := range []string{"user", "decision"} {
					if o[k] != j[k] || o[k] == "" {
						t.Errorf("OTel %s = %v, want %v", k, o[k], j[k])
					}
				}
				if want := strings.Join(bindings, ","); o["bindings"] != want || want == "" {
					t.Errorf("OTel bindings = %v, want %v", o["bindings"], want)
				}
				if id, _ := o["trace_id"].(trace.TraceID); !id.IsValid() {
					t.Error("OTel connect record carries no trace id")
				}
			}
			if err != nil {
				return
			}
			defer conn.Close(ctx)
			_, err = conn.Exec(ctx, tt.stmt)
			if (err == nil) != tt.wantStmt {
				t.Fatalf("%q error = %v, want ok %v", tt.stmt, err, tt.wantStmt)
			}
		})
	}
}

func TestAPI(t *testing.T) {
	_, store, _, apiSrv := startServer(t, func(cfg *config.Config) {
		cfg.Discovery = config.Discovery{CLIClientID: "pgauth-cli", Postgres: "pgauth.example.test:5432"}
	})
	var disc api.Discovery
	if code := getJSON(t, apiSrv, "/.well-known/pgauth", "", &disc); code != http.StatusOK {
		t.Fatalf("discovery: %d", code)
	}
	if disc.Postgres != "pgauth.example.test:5432" || disc.Issuer != shared.issuer.srv.URL || disc.Audience != audience ||
		disc.CLIClientID != "pgauth-cli" || disc.AccessHelp != "Ask in #data-access for a binding." || disc.Scopes != (api.Scopes{Read: "postgres:read", Write: "postgres:write"}) ||
		len(disc.Instances) != 1 || disc.Instances[0].Name != instanceName || strings.Join(disc.Instances[0].Databases, ",") != "order,assignment" {
		t.Fatalf("discovery = %+v", disc)
	}

	admins := binding("admins", "pg-admin", group("postgres-admins"))
	tests := []struct {
		name     string
		claims   claims
		bindings string
		code     int
		want     string // instance/db:level entries, comma-separated
	}{
		{"read scope caps pg-admin", claims{groups: []string{"postgres-admins"}}, admins, 200, "cloudsql-main/order:read,cloudsql-main/assignment:read"},
		{"write scope keeps write", claims{groups: []string{"postgres-admins"}, scope: "postgres:write"}, admins, 200, "cloudsql-main/order:write,cloudsql-main/assignment:write"},
		{"one database binding", claims{}, binding("mari", "cloudsql-main.order.read", user(defaultUser)), 200, "cloudsql-main/order:read"},
		{"no binding, empty list", claims{groups: []string{"interns"}}, admins, 200, ""},
		{"no postgres scope, empty list", claims{groups: []string{"postgres-admins"}, scope: "openid"}, admins, 200, ""},
		{"expired token", claims{expired: true}, admins, 401, ""},
		{"no token", claims{user: "-"}, admins, 401, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := store.Update([]rbac.File{{Name: "row.yaml", Data: []byte(tt.bindings)}}); err != nil {
				t.Fatal(err)
			}
			bearer := ""
			if tt.claims.user != "-" {
				bearer = shared.issuer.token(tt.claims)
			}
			var got []api.Access
			if code := getJSON(t, apiSrv, "/v1/access", bearer, &got); code != tt.code {
				t.Fatalf("status %d, want %d", code, tt.code)
			}
			var entries []string
			for _, a := range got {
				entries = append(entries, a.Instance+"/"+a.Database+":"+a.Level)
			}
			if strings.Join(entries, ",") != tt.want {
				t.Fatalf("access = %v, want %s", entries, tt.want)
			}
		})
	}
}

func TestStatsRole(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name      string
		statsRole string
		member    bool
	}{
		{"stats role set: temporary roles join it", "pgauth_stats", true},
		{"stats role unset: they do not", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			addr, _, _, _ := startServer(t, func(cfg *config.Config) { cfg.Instances[0].StatsRole = tt.statsRole })
			conn, err := connect(ctx, addr, "cloudsql-main/order", claims{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(ctx)
			var member bool
			if err := conn.QueryRow(ctx, "SELECT pg_has_role(current_user, 'pgauth_stats', 'MEMBER')").Scan(&member); err != nil {
				t.Fatal(err)
			}
			if member != tt.member {
				t.Fatalf("member of pgauth_stats = %v, want %v", member, tt.member)
			}
		})
	}
}

func TestDenial(t *testing.T) {
	for _, tt := range []struct{ help, want string }{
		{"", "no access to main/payment for luca@example.com: no binding grants it."},
		{"Ask in\n  #data-access\n", "no access to main/payment for luca@example.com: no binding grants it. Ask in #data-access"},
	} {
		if got := denial("main", "payment", "luca@example.com", tt.help); got != tt.want {
			t.Errorf("denial(help %q) = %q, want %q", tt.help, got, tt.want)
		}
	}
}

func getJSON(t *testing.T, srv *httptest.Server, path, bearer string, v any) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

func TestReleaseDropsRole(t *testing.T) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, shared.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	tempRoles := func() []string {
		rows, _ := admin.Query(ctx, `SELECT r.rolname || ' ' || shobj_description(r.oid, 'pg_authid') FROM pg_roles r
			WHERE pg_has_role(r.oid, 'pgauth_temp', 'MEMBER') AND r.rolcanlogin AND NOT r.rolsuper AND r.rolname <> 'pgauth'`)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	waitGone := func(t *testing.T) {
		deadline := time.Now().Add(5 * time.Second)
		for len(tempRoles()) > 0 {
			if time.Now().After(deadline) {
				t.Fatalf("temporary roles left: %v", tempRoles())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	c := claims{}

	t.Run("last close drops the role", func(t *testing.T) {
		addr, _, _, _ := startServer(t, nil)
		a, err := connect(ctx, addr, "cloudsql-main/order", c)
		if err != nil {
			t.Fatal(err)
		}
		b, err := connect(ctx, addr, "cloudsql-main/order", c)
		if err != nil {
			t.Fatal(err)
		}
		got := tempRoles()
		if len(got) != 1 || !strings.Contains(got[0], `"sub":"user-1234567890"`) || !strings.Contains(got[0], `"client":"poseidon-session"`) {
			t.Fatalf("want one commented role shared by both connections, got %v", got)
		}
		a.Close(ctx)
		time.Sleep(200 * time.Millisecond)
		if len(tempRoles()) != 1 {
			t.Fatal("role dropped while a connection still uses it")
		}
		b.Close(ctx)
		waitGone(t)
	})

	t.Run("max connection age closes and drops", func(t *testing.T) {
		addr, _, _, _ := startServer(t, func(cfg *config.Config) { cfg.MaxConnectionAge = config.Duration(300 * time.Millisecond) })
		conn, err := connect(ctx, addr, "cloudsql-main/order", c)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		waitGone(t)
		if _, err := conn.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("connection still open after max age")
		}
	})
}

// TestSweep seeds roles the way pgauth processes would leave them and checks which a starting
// pgauth removes: roles of dead owners, roles past any connection's life, roles without an owner.
func TestSweep(t *testing.T) {
	ctx := context.Background()
	issuerDSN := strings.Replace(shared.adminDSN, "postgres:postgres@", "pgauth:issuer-secret@", 1)
	// A live owner: this test holds the lock another pgauth process would.
	owner, err := pgx.Connect(ctx, shared.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	class, key := roles.OwnerLock("alive1")
	if _, err := owner.Exec(ctx, "SELECT pg_advisory_lock($1, $2)", class, key); err != nil {
		t.Fatal(err)
	}
	now, old := time.Now().UTC().Format(time.RFC3339), time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339)
	tests := []struct {
		role, comment string
		session       bool
		removed       bool
	}{
		{"pgauth_dead_owner", `{"pod":"dead01","created":"` + now + `"}`, true, true},
		{"pgauth_live_owner", `{"pod":"alive1","created":"` + now + `"}`, false, false},
		{"pgauth_live_but_too_old", `{"pod":"alive1","created":"` + old + `"}`, false, true},
		{"pgauth_from_v05", `{"sub":"x","client":"y","created":"` + now + `"}`, false, true},
	}
	for _, tt := range tests {
		err := execAll(ctx, issuerDSN, []string{
			fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'pw' IN ROLE pgauth_temp, order_read`, tt.role),
			fmt.Sprintf(`COMMENT ON ROLE %s IS '%s'`, tt.role, tt.comment),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := execAll(ctx, shared.adminDSN, []string{`CREATE ROLE pgauth_unmarked LOGIN`}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = execAll(ctx, shared.adminDSN, []string{`DROP ROLE IF EXISTS pgauth_unmarked`, `DROP ROLE IF EXISTS pgauth_live_owner`})
	}()
	sessions := map[string]*pgx.Conn{}
	for _, tt := range tests {
		if tt.session {
			c, err := pgx.Connect(ctx, directDSN(tt.role, "pw", "order"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close(ctx)
			sessions[tt.role] = c
		}
	}

	startServer(t, nil)

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			exists, _ := roleState(t, tt.role)
			if exists == tt.removed {
				t.Fatalf("role exists = %v, want removed = %v", exists, tt.removed)
			}
			if c := sessions[tt.role]; c != nil && tt.removed {
				if _, err := c.Exec(ctx, "SELECT 1"); err == nil {
					t.Fatal("the removed role's session still runs")
				}
			}
		})
	}
	if exists, _ := roleState(t, "pgauth_unmarked"); !exists {
		t.Fatal("a role outside pgauth_temp was removed")
	}
}

func directDSN(role, password, db string) string {
	dsn := strings.Replace(shared.adminDSN, "postgres:postgres@", role+":"+password+"@", 1)
	return strings.Replace(dsn, "/postgres?", "/"+db+"?", 1)
}

func roleState(t *testing.T, role string) (exists bool, canLogin bool) {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, shared.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	err = admin.QueryRow(ctx, `SELECT true, rolcanlogin FROM pg_roles WHERE rolname = $1`, role).Scan(&exists, &canLogin)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return exists, canLogin
}

// dropAsSuperuser removes a role pgauth had to leave behind, with whatever it owns.
func dropAsSuperuser(t *testing.T, role string) {
	ctx := context.Background()
	for _, db := range []string{"order", "assignment", "postgres"} {
		_ = execAll(ctx, strings.Replace(shared.adminDSN, "/postgres?", "/"+db+"?", 1), []string{fmt.Sprintf(`DROP OWNED BY %q`, role)})
	}
	_ = execAll(ctx, shared.adminDSN, []string{fmt.Sprintf(`DROP ROLE IF EXISTS %q`, role)})
}

// TestRevocation turns the security audit's probes into rows: a temporary role sets its own
// password or makes itself undroppable, and must still end with no way in once its last pgauth
// connection closes.
func TestRevocation(t *testing.T) {
	ctx := context.Background()
	addr, _, _, _ := startServer(t, nil)
	tests := []struct {
		name string
		stmt string // run by the temporary role before it changes its own password
	}{
		{"own password, direct session", ""},
		{"large object keeps the role", "SELECT lo_create(0)"},
		{"default privileges keep the role", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := connect(ctx, addr, "cloudsql-main/order", claims{})
			if err != nil {
				t.Fatal(err)
			}
			var role string
			if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil {
				t.Fatal(err)
			}
			defer dropAsSuperuser(t, role)
			if tt.stmt != "" {
				if _, err := conn.Exec(ctx, tt.stmt); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := conn.Exec(ctx, fmt.Sprintf(`ALTER ROLE %q PASSWORD 'mine'`, role)); err != nil {
				t.Fatal(err)
			}
			direct, err := pgx.Connect(ctx, directDSN(role, "mine", "order"))
			if err != nil {
				t.Fatalf("direct login while the pgauth connection is open: %v", err)
			}
			defer direct.Close(ctx)

			conn.Close(ctx)
			deadline := time.Now().Add(5 * time.Second)
			for {
				exists, canLogin := roleState(t, role)
				if !exists || !canLogin {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("role can still log in after its last pgauth connection closed")
				}
				time.Sleep(20 * time.Millisecond)
			}
			if _, err := direct.Exec(ctx, "SELECT count(*) FROM items"); err == nil {
				t.Fatal("the direct session survived the last close")
			}
			if c, err := pgx.Connect(ctx, directDSN(role, "mine", "order")); err == nil {
				c.Close(ctx)
				t.Fatal("a new direct login works after the last close")
			}
			if exists, _ := roleState(t, role); exists {
				var groups int
				admin, _ := pgx.Connect(ctx, shared.adminDSN)
				defer admin.Close(ctx)
				_ = admin.QueryRow(ctx, `SELECT count(*) FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.member
					JOIN pg_roles g ON g.oid = am.roleid WHERE r.rolname = $1 AND g.rolname <> 'pgauth_temp'`, role).Scan(&groups)
				if groups != 0 {
					t.Fatalf("a role pgauth could not drop still holds %d groups", groups)
				}
			}
		})
	}

	t.Run("reuse resets a self-set password", func(t *testing.T) {
		a, err := connect(ctx, addr, "cloudsql-main/order", claims{})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)
		var role string
		_ = a.QueryRow(ctx, "SELECT current_user").Scan(&role)
		if _, err := a.Exec(ctx, fmt.Sprintf(`ALTER ROLE %q PASSWORD 'mine'`, role)); err != nil {
			t.Fatal(err)
		}
		b, err := connect(ctx, addr, "cloudsql-main/order", claims{})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close(ctx)
		if c, err := pgx.Connect(ctx, directDSN(role, "mine", "order")); err == nil {
			c.Close(ctx)
			t.Fatal("the self-set password still works after pgauth reused the role")
		}
	})
}

func TestCaps(t *testing.T) {
	ctx := context.Background()
	open := func(t *testing.T, addr string, n int) (conns []*pgx.Conn, roles map[string]bool, err error) {
		roles = map[string]bool{}
		for range n {
			c, err := connect(ctx, addr, "cloudsql-main/order", claims{})
			if err != nil {
				return conns, roles, err
			}
			t.Cleanup(func() { c.Close(ctx) })
			var role string
			_ = c.QueryRow(ctx, "SELECT current_user").Scan(&role)
			conns, roles[role] = append(conns, c), true
		}
		return conns, roles, nil
	}

	t.Run("role connection limit: a full role is not shared further", func(t *testing.T) {
		addr, _, _, _ := startServer(t, func(cfg *config.Config) { cfg.RoleConnectionLimit = 2 })
		_, roleNames, err := open(t, addr, 3)
		if err != nil || len(roleNames) != 2 {
			t.Fatalf("3 connections used roles %v, err %v; want 2 roles", roleNames, err)
		}
		for role := range roleNames {
			var limit int
			var validUntil time.Time
			admin, _ := pgx.Connect(ctx, shared.adminDSN)
			defer admin.Close(ctx)
			if err := admin.QueryRow(ctx, "SELECT rolconnlimit, rolvaliduntil FROM pg_roles WHERE rolname = $1", role).Scan(&limit, &validUntil); err != nil {
				t.Fatal(err)
			}
			// The test token expires in 15 minutes; VALID UNTIL adds 5.
			if limit != 2 || time.Until(validUntil) < 19*time.Minute || time.Until(validUntil) > 21*time.Minute {
				t.Fatalf("%s: CONNECTION LIMIT %d, VALID UNTIL in %s", role, limit, time.Until(validUntil).Round(time.Second))
			}
		}
	})

	t.Run("connections per user", func(t *testing.T) {
		addr, _, _, _ := startServer(t, func(cfg *config.Config) { cfg.MaxConnectionsPerUser = 2 })
		_, _, err := open(t, addr, 3)
		if err == nil || !strings.Contains(err.Error(), "too many connections for mari@example.com (limit 2) (SQLSTATE 53300)") {
			t.Fatalf("third connection: %v", err)
		}
	})
}

func rssMB(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Skip("no /proc/self/statm")
	}
	pages, _ := strconv.Atoi(strings.Fields(string(b))[1])
	return pages * os.Getpagesize() >> 20
}

// TestPreAuthLimits sends what the audit sent before any token: a message claiming a huge length.
// pgauth must close the connection instead of buffering it.
func TestPreAuthLimits(t *testing.T) {
	addr, _, _, _ := startServer(t, nil)
	tests := []struct {
		name    string
		header  func(conn net.Conn) error // brings the conversation to where the message is sent
		message []byte
	}{
		{"password message of 1 GiB", func(conn net.Conn) error {
			startup, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersion30, Parameters: map[string]string{"user": "x", "database": "cloudsql-main/order"}}).Encode(nil)
			if _, err := conn.Write(startup); err != nil {
				return err
			}
			_, err := io.ReadFull(conn, make([]byte, 9)) // AuthenticationCleartextPassword
			return err
		}, []byte{'p', 0x40, 0, 0, 0}},
		{"startup message of 1 GiB", func(net.Conn) error { return nil }, []byte{0x40, 0, 0, 0, 0, 3, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			ssl, _ := (&pgproto3.SSLRequest{}).Encode(nil)
			resp := make([]byte, 1)
			if _, err := raw.Write(ssl); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(raw, resp); err != nil {
				t.Fatal(err)
			}
			conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
			if err := tt.header(conn); err != nil {
				t.Fatal(err)
			}
			before := rssMB(t)
			if _, err := conn.Write(tt.message); err != nil {
				t.Fatal(err)
			}
			chunk := make([]byte, 1<<20)
			sent := 0
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			for ; sent < 200; sent++ {
				if _, err := conn.Write(chunk); err != nil {
					break
				}
			}
			if sent == 200 {
				t.Fatal("pgauth kept reading a 1 GiB message before authentication")
			}
			if grown := rssMB(t) - before; grown > 32 {
				t.Fatalf("memory grew by %d MiB", grown)
			}
		})
	}
}

// TestRequireScram plays an upstream that asks for a password method and records whether pgauth
// answers with the issuer's password.
func TestRequireScram(t *testing.T) {
	no := false
	tests := []struct {
		name         string
		auth         pgproto3.BackendMessage
		requireScram *bool
		refused      bool // pgauth refuses before answering
		sendsSecret  bool // the secret password reached the server
	}{
		{"cleartext refused", &pgproto3.AuthenticationCleartextPassword{}, nil, true, false},
		{"md5 refused", &pgproto3.AuthenticationMD5Password{Salt: [4]byte{1, 2, 3, 4}}, nil, true, false},
		{"SCRAM proceeds", &pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}, nil, false, false},
		{"cleartext allowed when requireScram is off", &pgproto3.AuthenticationCleartextPassword{}, &no, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			got := make(chan []byte, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				b := pgproto3.NewBackend(c, c)
				if _, err := b.ReceiveStartupMessage(); err != nil {
					return
				}
				b.Send(tt.auth)
				_ = b.Flush()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				all, _ := io.ReadAll(c)
				got <- all
			}()
			_, port, _ := net.SplitHostPort(ln.Addr().String())
			p, _ := strconv.Atoi(port)
			in := config.Instance{Host: "127.0.0.1", Port: p, SSLMode: "disable", RequireScram: tt.requireScram}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = (&Server{}).dial(ctx, in, "pgauth", "issuer-secret", "postgres", nil)
			if refused := err != nil && strings.Contains(err.Error(), "requireScram"); refused != tt.refused {
				t.Fatalf("refused = %v (err %v), want %v", refused, err, tt.refused)
			}
			if sent := strings.Contains(string(<-got), "issuer-secret"); sent != tt.sendsSecret {
				t.Fatalf("secret sent = %v, want %v", sent, tt.sendsSecret)
			}
		})
	}
}

type memStore map[string]string

func (m memStore) Get(k string) (string, error) { return m[k], nil }
func (m memStore) Set(k, v string) error        { m[k] = v; return nil }
func (m memStore) Delete(k string) error        { delete(m, k); return nil }

func TestConnector(t *testing.T) {
	ctx := context.Background()
	server, _, _, _ := startServer(t, nil)
	store := memStore{}
	// startConnector serves two listeners from one connector: one without and one with an instance.
	startConnector := func() (plain, onInstance string) {
		c, err := pgconnect.New(pgconnect.Options{
			Issuer: shared.issuer.srv.URL, ClientID: "pgauth-cli", Resource: audience, Scope: "openid offline_access",
			Server: server, ServerCA: shared.certFile, Store: store,
			OpenBrowser: func(u string) error {
				go func() {
					if resp, err := http.Get(u); err == nil {
						resp.Body.Close()
					}
				}()
				return nil
			},
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		cctx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		t.Cleanup(func() { cancel(); wg.Wait() })
		addrs := make([]string, 2)
		for i, instance := range []string{"", instanceName} {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addrs[i] = ln.Addr().String()
			wg.Go(func() { _ = c.Serve(cctx, ln, instance) })
		}
		return addrs[0], addrs[1]
	}
	query := func(addr, db string) (string, error) {
		host, port, _ := net.SplitHostPort(addr)
		conn, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s dbname=%s user=me sslmode=prefer", host, port, db))
		if err != nil {
			return "", err
		}
		defer conn.Close(ctx)
		var user string
		err = conn.QueryRow(ctx, "SELECT current_user FROM items LIMIT 1").Scan(&user)
		return user, err
	}
	counts := func() (int, int) {
		shared.issuer.mu.Lock()
		defer shared.issuer.mu.Unlock()
		return shared.issuer.logins, shared.issuer.refreshes
	}
	logins0, refreshes0 := counts()

	first, firstInstance := startConnector()
	for _, q := range []struct{ addr, db string }{
		{first, "cloudsql-main/order"},
		{first, "cloudsql-main/order"},
		{firstInstance, "order"},
		{firstInstance, "cloudsql-main/assignment"},
	} {
		if user, err := query(q.addr, q.db); err != nil || !strings.HasPrefix(user, "pgauth_") {
			t.Fatalf("query %s through connector: user %q, err %v", q.db, user, err)
		}
	}
	if _, err := query(first, "order"); err == nil || !strings.Contains(err.Error(), "<instance>/<db>") {
		t.Fatalf("a bare name on a listener without instance must reach pgauth unchanged, got %v", err)
	}
	if _, err := query(first, "cloudsql-main/postgres"); err == nil || !strings.Contains(err.Error(), "not served") {
		t.Fatalf("want pgauth's denial passed through, got %v", err)
	}
	if l, r := counts(); l-logins0 != 1 || r-refreshes0 != 0 {
		t.Fatalf("first connector: %d logins, %d refreshes; want one login shared by both listeners", l-logins0, r-refreshes0)
	}

	second, _ := startConnector()
	if _, err := query(second, "cloudsql-main/order"); err != nil {
		t.Fatal(err)
	}
	if l, r := counts(); l-logins0 != 1 || r-refreshes0 != 1 {
		t.Fatalf("second connector: %d logins, %d refreshes; want the stored refresh token used", l-logins0, r-refreshes0)
	}
}

// TestConnectorEnvironments runs a connector in environment mode against serve, with a token file
// that changes between rows; the connector never restarts.
func TestConnectorEnvironments(t *testing.T) {
	ctx := context.Background()
	server, _, _, apiSrv := startServer(t, nil)
	dir := t.TempDir()
	tokenFile, statusFile := filepath.Join(dir, "token.json"), filepath.Join(dir, "token.status")
	f := &pgconnect.File{Environments: map[string]*pgconnect.EnvConfig{"test": {
		Server: server, API: apiSrv.URL, ServerCA: shared.certFile,
		Token: pgconnect.TokenConfig{File: tokenFile, Field: "access_token", StatusFile: statusFile},
	}}}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	envs, err := f.BuildEnvs(pgconnect.BuildOptions{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	router := pgconnect.NewRouter(envs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait() })
	addrs := map[string]string{} // listener env ("" = main) -> address
	for _, env := range []string{"", "test"} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[env] = ln.Addr().String()
		wg.Go(func() { _ = router.Serve(cctx, ln, env) })
	}

	writeToken := func(c *claims) {
		if c == nil {
			_ = os.Remove(tokenFile)
			return
		}
		b, _ := json.Marshal(map[string]string{"access_token": shared.issuer.token(*c)})
		if err := os.WriteFile(tokenFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(statusFile, []byte("Rapidata test is not connected: open Settings → Connections\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		token   *claims // nil: no token file
		port    string  // listener: "" main, "test" the IDE port bound to test
		db      string
		wantErr string // substring of the client's error; empty: SELECT works
	}{
		{"missing token file shows the status file", nil, "", "test/order", "Rapidata test is not connected: open Settings → Connections (SQLSTATE 28000)"},
		{"token written later is picked up", &claims{}, "", "test/order", ""},
		{"instance-qualified address", &claims{}, "", "test/cloudsql-main/assignment", ""},
		{"bare database names the environments", &claims{}, "", "order", "use <env>/<db>; environments: test"},
		{"unknown database", &claims{}, "", "test/billing", "test serves no database billing"},
		{"denial passes through with help", &claims{user: "nobody@example.com"}, "", "test/order",
			"FATAL: pgauth: no access to cloudsql-main/order for nobody@example.com: no binding grants it. Ask in #data-access for a binding. (SQLSTATE 28000)"},
		{"denial passes through on the IDE port", &claims{user: "nobody@example.com"}, "test", "assignment",
			"FATAL: pgauth: no access to cloudsql-main/assignment for nobody@example.com: no binding grants it. Ask in #data-access for a binding. (SQLSTATE 28000)"},
		{"expired token shows the status file", &claims{expired: true}, "", "test/order", "Rapidata test is not connected"},
		{"fixed again", &claims{}, "", "test/order", ""},
		{"bare name on the test IDE port", &claims{}, "test", "order", ""},
		{"instance name on the test IDE port", &claims{}, "test", "cloudsql-main/assignment", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeToken(tt.token)
			host, port, _ := net.SplitHostPort(addrs[tt.port])
			conn, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s dbname=%s user=me sslmode=disable", host, port, tt.db))
			if err == nil {
				defer conn.Close(ctx)
				_, err = conn.Exec(ctx, "SELECT count(*) FROM items")
			}
			if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}

	for _, tt := range []struct {
		name  string
		token claims
		want  string
	}{
		{"ls lists reachable databases", claims{}, "test/order       read\ntest/assignment  read\n"},
		{"ls with nothing reachable shows the help", claims{user: "nobody@example.com"},
			"DATABASE  LEVEL\ntest: no database is reachable with this token. Ask in #data-access for a binding.\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			writeToken(&tt.token)
			var out, errOut strings.Builder
			if err := router.PrintAccess(ctx, &out, &errOut, []string{"test"}); err != nil || !strings.Contains(out.String(), tt.want) {
				t.Fatalf("ls output:\n%s\nerr %v %s; want it to contain:\n%s", out.String(), err, errOut.String(), tt.want)
			}
		})
	}
}

type issuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu         sync.Mutex
	challenges map[string]string // code -> PKCE challenge
	logins     int
	refreshes  int
}

func newIssuer() *issuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	is := &issuer{key: key, challenges: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": is.srv.URL, "jwks_uri": is.srv.URL + "/jwks",
			"authorization_endpoint": is.srv.URL + "/authorize", "token_endpoint": is.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := rand.Text()
		is.mu.Lock()
		is.challenges[code] = q.Get("code_challenge")
		is.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		is.mu.Lock()
		defer is.mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if is.challenges[r.Form.Get("code")] != base64.RawURLEncoding.EncodeToString(sum[:]) {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			is.logins++
		case "refresh_token":
			if !strings.HasPrefix(r.Form.Get("refresh_token"), "refresh-") {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			is.refreshes++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  is.token(claims{client: r.Form.Get("client_id"), audience: r.Form.Get("resource")}),
			"refresh_token": "refresh-" + rand.Text(), "expires_in": 3600, "token_type": "Bearer",
		})
	})
	is.srv = httptest.NewServer(mux)
	return is
}

func (is *issuer) token(c claims) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: is.key, KeyID: "k1"}}, nil)
	if err != nil {
		panic(err)
	}
	if c.client == "" {
		c.client = "poseidon-session"
	}
	if c.audience == "" {
		c.audience = audience
	}
	if c.user == "" {
		c.user = defaultUser
	}
	if c.scope == "" {
		c.scope = "postgres:read"
	}
	exp := time.Now().Add(15 * time.Minute)
	if c.expired {
		exp = time.Now().Add(-time.Minute)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": is.srv.URL, "sub": "user-1234567890", "aud": c.audience, "client_id": c.client,
		"exp": exp.Unix(), "iat": time.Now().Add(-time.Hour).Unix(),
		"email": c.user, "groups": groupsClaim(c), "scope": c.scope,
	}).Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

func groupsClaim(c claims) any {
	if c.group != "" {
		return c.group
	}
	return c.groups
}

func writeCert(dir string) (certFile, keyFile string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return "", "", err
	}
	return certFile, keyFile, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
}

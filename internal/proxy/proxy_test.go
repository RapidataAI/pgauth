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
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/RapidataAI/pgauth/internal/config"
	pgconnect "github.com/RapidataAI/pgauth/internal/connect"
	"github.com/RapidataAI/pgauth/internal/rbac"
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
func startServer(t *testing.T, mutate func(*config.Config)) (string, *rbac.Store) {
	t.Helper()
	cfg := &config.Config{
		TLS: config.TLS{CertFile: shared.certFile, KeyFile: shared.keyFile},
		OIDC: config.OIDC{
			Issuer: shared.issuer.srv.URL, Audience: audience,
			AllowedClients: []string{"poseidon-session", "pgauth-cli"},
		},
		RBAC: config.RBAC{Dir: "unused-in-tests"},
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
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
	return ln.Addr().String(), store
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
	addr, store := startServer(t, nil)
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
	}{
		{"user binding reads", claims{}, mariOrderRead, "cloudsql-main/order", "SELECT count(*) FROM items", true, true},
		{"read binding cannot insert", claims{scope: "postgres:write"}, mariOrderRead, "cloudsql-main/order", "INSERT INTO items VALUES (2)", true, false},
		{"read binding cannot switch to the write group", claims{}, mariOrderRead, "cloudsql-main/order", "SET ROLE order_write", true, false},
		{"binding on one database does not open another", claims{}, mariOrderRead, "cloudsql-main/assignment", "", false, false},
		{"user names match case-insensitively", claims{user: "MARI@Example.com"}, mariOrderRead, "cloudsql-main/order", "SELECT 1", true, true},
		{"groups claim as a single string", claims{user: "ada@example.com", group: "postgres-admins", scope: "postgres:write"}, admins, "cloudsql-main/order", "UPDATE items SET id = id", true, true},
		{"single-string group must match whole", claims{user: "ada@example.com", group: "postgres-admins interns"}, admins, "cloudsql-main/order", "", false, false},
		{"write binding with write scope updates", claims{scope: "postgres:write"}, mariOrderWrite, "cloudsql-main/order", "UPDATE items SET id = id", true, true},
		{"write binding still reads", claims{scope: "postgres:write"}, mariOrderWrite, "cloudsql-main/order", "SELECT count(*) FROM items", true, true},
		{"group pg-admin inserts with write scope", claims{user: "ada@example.com", groups: admin, scope: "postgres:write"}, admins, "cloudsql-main/assignment", "INSERT INTO items VALUES (3)", true, true},
		{"read scope caps pg-admin at read", claims{user: "ada@example.com", groups: admin, scope: "openid postgres:read"}, admins, "cloudsql-main/order", "INSERT INTO items VALUES (4)", true, false},
		{"no postgres scope is refused", claims{user: "ada@example.com", groups: admin, scope: "openid"}, admins, "cloudsql-main/order", "", false, false},
		{"pg-admin cannot create tables", claims{groups: admin, scope: "postgres:write"}, admins, "cloudsql-main/order", "CREATE TABLE t (id int)", true, false},
		{"pg-admin cannot drop tables", claims{groups: admin, scope: "postgres:write"}, admins, "cloudsql-main/order", "DROP TABLE items", true, false},
		{"pg-reader with write scope stays read", claims{groups: admin, scope: "postgres:write"}, readers, "cloudsql-main/order", "DELETE FROM items", true, false},
		{"union of bindings takes the highest level", claims{groups: admin, scope: "postgres:write"}, readers + mariOrderWrite, "cloudsql-main/order", "UPDATE items SET id = id", true, true},
		{"custom role with database * reads every database", claims{user: "bo@example.com", groups: []string{"analysts"}}, analysts, "cloudsql-main/assignment", "SELECT count(*) FROM items", true, true},
		{"other group matches nothing", claims{user: "bo@example.com", groups: []string{"interns"}}, admins + analysts, "cloudsql-main/order", "", false, false},
		{"pgauth-cli client is allowed", claims{client: "pgauth-cli"}, mariOrderRead, "cloudsql-main/order", "SELECT 1", true, true},
		{"client outside the allowlist", claims{client: "other-app"}, mariOrderRead, "cloudsql-main/order", "", false, false},
		{"expired token", claims{expired: true}, mariOrderRead, "cloudsql-main/order", "", false, false},
		{"token for another audience", claims{audience: "https://api.example.test"}, mariOrderRead, "cloudsql-main/order", "", false, false},
		{"unknown instance", claims{groups: admin}, admins, "other/order", "", false, false},
		{"database not served", claims{groups: admin}, admins, "cloudsql-main/postgres", "", false, false},
		{"database without instance", claims{groups: admin}, admins, "order", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if err := store.Update([]rbac.File{{Name: "row.yaml", Data: []byte(tt.bindings)}}); err != nil {
				t.Fatalf("bindings: %v", err)
			}
			conn, err := connect(ctx, addr, tt.db, tt.claims)
			if (err == nil) != tt.wantConnect {
				t.Fatalf("connect error = %v, want connect %v", err, tt.wantConnect)
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
		addr, _ := startServer(t, nil)
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
		addr, _ := startServer(t, func(cfg *config.Config) { cfg.MaxConnectionAge = config.Duration(300 * time.Millisecond) })
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

func TestSweep(t *testing.T) {
	ctx := context.Background()
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	young := time.Now().UTC().Format(time.RFC3339)
	issuerDSN := strings.Replace(shared.adminDSN, "postgres:postgres@", "pgauth:issuer-secret@", 1)
	err := execAll(ctx, issuerDSN, []string{
		`CREATE ROLE pgauth_old LOGIN IN ROLE pgauth_temp`,
		`COMMENT ON ROLE pgauth_old IS '{"sub":"x","client":"y","created":"` + old + `"}'`,
		`CREATE ROLE pgauth_young LOGIN IN ROLE pgauth_temp`,
		`COMMENT ON ROLE pgauth_young IS '{"sub":"x","client":"y","created":"` + young + `"}'`,
		`CREATE ROLE pgauth_busy LOGIN PASSWORD 'busy' IN ROLE pgauth_temp, order_read`,
		`COMMENT ON ROLE pgauth_busy IS '{"sub":"x","client":"y","created":"` + old + `"}'`,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = execAll(ctx, shared.adminDSN, []string{`CREATE ROLE pgauth_unmarked LOGIN`})
	if err != nil {
		t.Fatal(err)
	}
	busy, err := pgx.Connect(ctx, strings.Replace(strings.Replace(shared.adminDSN, "postgres:postgres@", "pgauth_busy:busy@", 1), "/postgres?", "/order?", 1))
	if err != nil {
		t.Fatal(err)
	}
	startServer(t, nil)
	busy.Close(ctx)

	rows, _ := pgx.Connect(ctx, shared.adminDSN)
	defer rows.Close(ctx)
	r, _ := rows.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolname IN ('pgauth_old', 'pgauth_young', 'pgauth_busy', 'pgauth_unmarked') ORDER BY 1`)
	left, err := pgx.CollectRows(r, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if want := "pgauth_busy pgauth_unmarked pgauth_young"; strings.Join(left, " ") != want {
		t.Fatalf("roles left = %v, want %s", left, want)
	}
	_ = execAll(ctx, shared.adminDSN, []string{`DROP ROLE pgauth_busy`, `DROP ROLE pgauth_young`, `DROP ROLE pgauth_unmarked`})
}

type memStore map[string]string

func (m memStore) Get(k string) (string, error) { return m[k], nil }
func (m memStore) Set(k, v string) error        { m[k] = v; return nil }

func TestConnector(t *testing.T) {
	ctx := context.Background()
	server, _ := startServer(t, nil)
	store := memStore{}
	startConnector := func() string {
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
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		cctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); _ = c.Serve(cctx, ln) }()
		t.Cleanup(func() { cancel(); <-done })
		return ln.Addr().String()
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

	first := startConnector()
	for range 2 {
		if user, err := query(first, "cloudsql-main/order"); err != nil || !strings.HasPrefix(user, "pgauth_") {
			t.Fatalf("query through connector: user %q, err %v", user, err)
		}
	}
	if _, err := query(first, "cloudsql-main/postgres"); err == nil || !strings.Contains(err.Error(), "not served") {
		t.Fatalf("want pgauth's denial passed through, got %v", err)
	}
	if l, r := counts(); l-logins0 != 1 || r-refreshes0 != 0 {
		t.Fatalf("first connector: %d logins, %d refreshes; want one login reused for every connection", l-logins0, r-refreshes0)
	}

	second := startConnector()
	if _, err := query(second, "cloudsql-main/order"); err != nil {
		t.Fatal(err)
	}
	if l, r := counts(); l-logins0 != 1 || r-refreshes0 != 1 {
		t.Fatalf("second connector: %d logins, %d refreshes; want the stored refresh token used", l-logins0, r-refreshes0)
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

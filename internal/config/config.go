// Package config loads the YAML configuration of `pgauth serve`.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

type Config struct {
	Listen string `json:"listen"`
	// Health serves GET /healthz and /readyz; empty disables it.
	Health string `json:"health"`
	// AccessHelp is appended to every "no binding grants it" denial and shown by `pgauth ls` when
	// nothing is reachable: where to ask for access.
	AccessHelp string `json:"accessHelp"`
	// HTTP serves discovery and access over HTTPS with the Postgres certificate; empty disables it.
	HTTP      HTTP      `json:"http"`
	Discovery Discovery `json:"discovery"`
	TLS       TLS       `json:"tls"`
	OIDC      OIDC      `json:"oidc"`
	RBAC      RBAC      `json:"rbac"`
	// GroupRoles names the Postgres group role per access level; "{db}" is replaced by the database name.
	GroupRoles GroupRoles `json:"groupRoles"`
	// TempGroup marks every temporary role so pgauth can find and sweep them.
	TempGroup        string   `json:"tempGroup"`
	RolePrefix       string   `json:"rolePrefix"`
	MaxConnectionAge Duration `json:"maxConnectionAge"`
	// SweepMinAge is ignored since v0.6.0; roles belong to the process that made them.
	SweepMinAge   Duration `json:"sweepMinAge"`
	SweepInterval Duration `json:"sweepInterval"`
	// RoleConnectionLimit is each temporary role's CONNECTION LIMIT and how many connections share one.
	RoleConnectionLimit int `json:"roleConnectionLimit"`
	// MaxConnectionsPerUser caps one subject's open connections through this pgauth.
	MaxConnectionsPerUser int        `json:"maxConnectionsPerUser"`
	Instances             []Instance `json:"instances"`
}

type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type HTTP struct {
	Listen string `json:"listen"`
}

// Discovery is what GET /.well-known/pgauth tells a connector beyond the OIDC settings.
type Discovery struct {
	// CLIClientID is the public OIDC client people log in with.
	CLIClientID string `json:"cliClientId"`
	// Postgres is the address clients reach the Postgres port at; default: the request's host and the listen port.
	Postgres string `json:"postgres"`
}

type RBAC struct {
	// Dir holds the PgRole / PgRoleBinding YAML; it is reread when it changes.
	Dir            string   `json:"dir"`
	ReloadInterval Duration `json:"reloadInterval"`
}

type GroupRoles struct {
	Read  string `json:"read"`
	Write string `json:"write"`
}

type OIDC struct {
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	UsernameClaim string `json:"usernameClaim"`
	// UsernameCaseInsensitive compares User subjects to the username ignoring case; nil means true.
	UsernameCaseInsensitive *bool  `json:"usernameCaseInsensitive"`
	GroupsClaim             string `json:"groupsClaim"`
	// GroupsPrefix is prepended to every group from the token before bindings are matched.
	GroupsPrefix  string `json:"groupsPrefix"`
	Scopes        Scopes `json:"scopes"`
	ClientIDClaim string `json:"clientIdClaim"`
	// AllowedClients restricts the client a token was issued to; empty allows any.
	AllowedClients []string `json:"allowedClients"`
}

// Scopes are the token scopes that cap access at read or allow write; a token with neither is refused.
type Scopes struct {
	Read  string `json:"read"`
	Write string `json:"write"`
}

type Instance struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	SSLMode     string `json:"sslmode"`
	SSLRootCert string `json:"sslrootcert"`
	// AdminDatabase is where the issuer login connects to manage roles.
	AdminDatabase string   `json:"adminDatabase"`
	Databases     []string `json:"databases"`
	// CredentialsFile is a JSON file {"username": ..., "password": ...} for the issuer login.
	CredentialsFile string `json:"credentialsFile"`
	// StatsRole, when set, is joined by every temporary role on this instance (e.g. for query
	// statistics); the issuer needs ADMIN on it.
	StatsRole string `json:"statsRole"`
	// RequireScram refuses any upstream password method but SCRAM-SHA-256; nil means true.
	RequireScram *bool `json:"requireScram"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Duration accepts Go duration strings such as "12h".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = ":5432"
	}
	if c.OIDC.ClientIDClaim == "" {
		c.OIDC.ClientIDClaim = "client_id"
	}
	if c.OIDC.UsernameClaim == "" {
		c.OIDC.UsernameClaim = "email"
	}
	if c.OIDC.GroupsClaim == "" {
		c.OIDC.GroupsClaim = "groups"
	}
	if c.OIDC.Scopes.Read == "" {
		c.OIDC.Scopes.Read = "postgres:read"
	}
	if c.OIDC.Scopes.Write == "" {
		c.OIDC.Scopes.Write = "postgres:write"
	}
	if c.GroupRoles.Read == "" {
		c.GroupRoles.Read = "{db}_read"
	}
	if c.GroupRoles.Write == "" {
		c.GroupRoles.Write = "{db}_write"
	}
	if c.RBAC.ReloadInterval == 0 {
		c.RBAC.ReloadInterval = Duration(10 * time.Second)
	}
	if c.TempGroup == "" {
		c.TempGroup = "pgauth_temp"
	}
	if c.RolePrefix == "" {
		c.RolePrefix = "pgauth_"
	}
	if c.MaxConnectionAge == 0 {
		c.MaxConnectionAge = Duration(12 * time.Hour)
	}
	if c.SweepInterval == 0 {
		c.SweepInterval = Duration(time.Minute)
	}
	if c.RoleConnectionLimit == 0 {
		c.RoleConnectionLimit = 20
	}
	if c.MaxConnectionsPerUser == 0 {
		c.MaxConnectionsPerUser = 50
	}
	for i := range c.Instances {
		in := &c.Instances[i]
		if in.Port == 0 {
			in.Port = 5432
		}
		if in.SSLMode == "" {
			in.SSLMode = "verify-full"
		}
		if in.AdminDatabase == "" {
			in.AdminDatabase = "postgres"
		}
	}
}

func (c *Config) Validate() error {
	var errs []error
	req := func(v, name string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	req(c.TLS.CertFile, "tls.certFile")
	req(c.TLS.KeyFile, "tls.keyFile")
	req(c.OIDC.Issuer, "oidc.issuer")
	req(c.OIDC.Audience, "oidc.audience")
	req(c.RBAC.Dir, "rbac.dir")
	if len(c.Instances) == 0 {
		errs = append(errs, errors.New("instances needs at least one entry"))
	}
	seen := map[string]bool{}
	for i, in := range c.Instances {
		if in.Name == "" || strings.Contains(in.Name, "/") || seen[in.Name] {
			errs = append(errs, fmt.Errorf("instances[%d].name %q must be unique, non-empty and contain no '/'", i, in.Name))
		}
		seen[in.Name] = true
		req(in.Host, fmt.Sprintf("instances[%d].host", i))
		req(in.CredentialsFile, fmt.Sprintf("instances[%d].credentialsFile", i))
		if len(in.Databases) == 0 {
			errs = append(errs, fmt.Errorf("instances[%d].databases must list the databases pgauth serves", i))
		}
	}
	return errors.Join(errs...)
}

func (c *Config) Instance(name string) (Instance, bool) {
	for _, in := range c.Instances {
		if in.Name == name {
			return in, true
		}
	}
	return Instance{}, false
}

// GroupRole returns the group role for one level ("read" or "write") on db.
func (c *Config) GroupRole(level, db string) string {
	tmpl := c.GroupRoles.Read
	if level == "write" {
		tmpl = c.GroupRoles.Write
	}
	return strings.ReplaceAll(tmpl, "{db}", db)
}

func (o OIDC) FoldUsername() bool {
	return o.UsernameCaseInsensitive == nil || *o.UsernameCaseInsensitive
}

// Databases maps every instance to the databases pgauth serves on it.
func (c *Config) Databases() map[string][]string {
	out := make(map[string][]string, len(c.Instances))
	for _, in := range c.Instances {
		out[in.Name] = in.Databases
	}
	return out
}

func (in Instance) ScramOnly() bool { return in.RequireScram == nil || *in.RequireScram }

func (in Instance) Serves(db string) bool { return slices.Contains(in.Databases, db) }

// ConnString is a libpq keyword/value string for user on db.
func (in Instance) ConnString(user, password, db string) string {
	kv := []string{
		"host=" + quote(in.Host),
		"port=" + strconv.Itoa(in.Port),
		"user=" + quote(user),
		"password=" + quote(password),
		"dbname=" + quote(db),
		"sslmode=" + quote(in.SSLMode),
	}
	if in.SSLRootCert != "" {
		kv = append(kv, "sslrootcert="+quote(in.SSLRootCert))
	}
	return strings.Join(kv, " ")
}

func (in Instance) Credentials() (Credentials, error) {
	b, err := os.ReadFile(in.CredentialsFile)
	if err != nil {
		return Credentials{}, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return Credentials{}, fmt.Errorf("parse %s: %w", in.CredentialsFile, err)
	}
	if c.Username == "" || c.Password == "" {
		return Credentials{}, fmt.Errorf("%s needs username and password", in.CredentialsFile)
	}
	return c, nil
}

func quote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

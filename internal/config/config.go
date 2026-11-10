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
	TLS    TLS    `json:"tls"`
	OIDC   OIDC   `json:"oidc"`
	// Groups maps a relation from the roles claim to a group role; "{db}" is replaced by the database name.
	Groups map[string]string `json:"groups"`
	// TempGroup marks every temporary role so pgauth can find and sweep them.
	TempGroup        string     `json:"tempGroup"`
	RolePrefix       string     `json:"rolePrefix"`
	MaxConnectionAge Duration   `json:"maxConnectionAge"`
	SweepMinAge      Duration   `json:"sweepMinAge"`
	Instances        []Instance `json:"instances"`
}

type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type OIDC struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// RolesClaim holds entries "<instance>/<db>:<relation>", as a JSON array or a space-separated string.
	RolesClaim    string `json:"rolesClaim"`
	ClientIDClaim string `json:"clientIdClaim"`
	// AllowedClients restricts the client a token was issued to; empty allows any.
	AllowedClients []string `json:"allowedClients"`
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
	if len(c.Groups) == 0 {
		c.Groups = map[string]string{"reader": "{db}_read", "writer": "{db}_write"}
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
	if c.SweepMinAge == 0 {
		c.SweepMinAge = Duration(5 * time.Minute)
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
	req(c.OIDC.RolesClaim, "oidc.rolesClaim")
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

// Group returns the group role for relation on db, or "" when the relation is not mapped.
func (c *Config) Group(relation, db string) string {
	tmpl, ok := c.Groups[relation]
	if !ok {
		return ""
	}
	return strings.ReplaceAll(tmpl, "{db}", db)
}

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

package connect

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/RapidataAI/pgauth/internal/api"
)

// File is connect.yaml.
type File struct {
	Listen       string                `json:"listen,omitempty"`
	ServerCA     string                `json:"serverCA,omitempty"`
	CallbackPort *int                  `json:"callbackPort,omitempty"`
	Environments map[string]*EnvConfig `json:"environments,omitempty"`

	// The v0.4 single-server format, still loaded with a warning.
	Issuer    string     `json:"issuer,omitempty"`
	ClientID  string     `json:"clientId,omitempty"`
	Resource  string     `json:"resource,omitempty"`
	Scope     string     `json:"scope,omitempty"`
	Server    string     `json:"server,omitempty"`
	Listeners []Listener `json:"listeners,omitempty"`
}

type EnvConfig struct {
	Server string `json:"server"`
	// API is serve's HTTPS base URL; default https://<server host>:8443.
	API      string      `json:"api,omitempty"`
	ServerCA string      `json:"serverCA,omitempty"`
	Token    TokenConfig `json:"token"`
}

// TokenConfig is either a browser login or a file; there is no way to run a command (ADR 0009).
type TokenConfig struct {
	Login      string `json:"login,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	ClientID   string `json:"clientId,omitempty"`
	Resource   string `json:"resource,omitempty"`
	Scope      string `json:"scope,omitempty"`
	File       string `json:"file,omitempty"`
	Field      string `json:"field,omitempty"`
	StatusFile string `json:"statusFile,omitempty"`
}

// DefaultAPIPort is where serve's HTTPS endpoints listen unless an address says otherwise.
const DefaultAPIPort = "8443"

// LoadFile reads connect.yaml; a missing file is an empty config.
func LoadFile(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &f, nil
}

func (f *File) Save(path string) error {
	b, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Legacy reports a v0.4 config: no environments, but a server or listeners.
func (f *File) Legacy() bool {
	return len(f.Environments) == 0 && (f.Server != "" || f.Issuer != "" || len(f.Listeners) > 0)
}

func (f *File) EnvNames() []string {
	names := make([]string, 0, len(f.Environments))
	for n := range f.Environments {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (f *File) Validate() error {
	if len(f.Environments) == 0 {
		return errors.New("no environments; add one with `pgauth env add <name> <host>`")
	}
	var errs []error
	for _, name := range f.EnvNames() {
		e := f.Environments[name]
		if name == "" || strings.Contains(name, "/") {
			errs = append(errs, fmt.Errorf("environment %q: name must be non-empty without '/'", name))
		}
		if e == nil {
			errs = append(errs, fmt.Errorf("environment %s is empty", name))
			continue
		}
		if _, _, err := net.SplitHostPort(e.Server); err != nil {
			errs = append(errs, fmt.Errorf("environment %s: server %q must be host:port", name, e.Server))
		}
		t := e.Token
		switch {
		case t.Login != "" && t.File != "":
			errs = append(errs, fmt.Errorf("environment %s: token has both login and file", name))
		case t.Login == "browser":
			if t.Issuer == "" || t.ClientID == "" {
				errs = append(errs, fmt.Errorf("environment %s: a browser login needs issuer and clientId", name))
			}
		case t.Login != "":
			errs = append(errs, fmt.Errorf("environment %s: token.login must be browser, got %s", name, t.Login))
		case t.File == "":
			errs = append(errs, fmt.Errorf("environment %s: token needs login: browser or a file", name))
		}
	}
	return errors.Join(errs...)
}

// APIURL is the environment's HTTPS base URL.
func (e *EnvConfig) APIURL() string {
	if e.API != "" {
		return strings.TrimSuffix(e.API, "/")
	}
	host, _, _ := net.SplitHostPort(e.Server)
	return "https://" + net.JoinHostPort(host, DefaultAPIPort)
}

// KeychainKey names an environment's refresh token in the OS keychain.
func KeychainKey(name string, t TokenConfig) string {
	return "env/" + name + " " + t.Issuer + " " + t.ClientID
}

// AddOptions are the flags of `pgauth env add`.
type AddOptions struct {
	CA    string
	Write bool
	Force bool
}

// AddEnv writes environment name from serve's discovery, pinning the issuer and client: an
// existing environment whose issuer or token source would change is refused without Force.
func AddEnv(f *File, name, apiURL string, d *api.Discovery, o AddOptions) error {
	if name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("environment name %q must be non-empty without '/'", name)
	}
	if d.CLIClientID == "" || d.Issuer == "" || d.Postgres == "" {
		return errors.New("the server's discovery has no cli_client_id, issuer or postgres address")
	}
	if old := f.Environments[name]; old != nil && !o.Force {
		switch {
		case old.Token.File != "":
			return fmt.Errorf("environment %s reads its token from %s; use --force to switch it to a browser login", name, old.Token.File)
		case old.Token.Issuer != d.Issuer:
			return fmt.Errorf("environment %s is pinned to issuer %s but the server now names %s; use --force if that is expected", name, old.Token.Issuer, d.Issuer)
		}
	}
	scope := d.Scopes.Read
	if o.Write {
		scope = d.Scopes.Write
	}
	if f.Environments == nil {
		f.Environments = map[string]*EnvConfig{}
	}
	f.Environments[name] = &EnvConfig{
		Server:   d.Postgres,
		API:      apiURL,
		ServerCA: o.CA,
		Token: TokenConfig{
			Login: "browser", Issuer: d.Issuer, ClientID: d.CLIClientID, Resource: d.Audience,
			Scope: strings.TrimSpace("openid offline_access " + scope),
		},
	}
	return nil
}

// BuildOptions carry what the environments' browser logins need.
type BuildOptions struct {
	Store        TokenStore
	OpenBrowser  func(url string) error
	CallbackPort int
	Log          *slog.Logger
}

// BuildEnvs turns a validated config into environments ready to serve.
func (f *File) BuildEnvs(o BuildOptions) ([]*Env, error) {
	var envs []*Env
	for _, name := range f.EnvNames() {
		ec := f.Environments[name]
		ca := ec.ServerCA
		if ca == "" {
			ca = f.ServerCA
		}
		roots, err := loadCA(ca)
		if err != nil {
			return nil, fmt.Errorf("environment %s: %w", name, err)
		}
		host, _, _ := net.SplitHostPort(ec.Server)
		up := &upstream{server: ec.Server, tls: &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12}}
		if t := ec.Token; t.File != "" {
			up.tokens = &FileSource{Path: t.File, Field: t.Field, StatusFile: t.StatusFile}
		} else {
			c, err := New(Options{
				Issuer: t.Issuer, ClientID: t.ClientID, Resource: t.Resource, Scope: t.Scope, Server: ec.Server, ServerCA: ca,
				CallbackPort: o.CallbackPort, OpenBrowser: o.OpenBrowser, Store: o.Store, StoreKey: KeychainKey(name, t),
			}, o.Log)
			if err != nil {
				return nil, fmt.Errorf("environment %s: %w", name, err)
			}
			up.tokens = c
		}
		envs = append(envs, &Env{
			Name: name, up: up, API: ec.APIURL(),
			HTTP: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}},
		})
	}
	return envs, nil
}

// HTTPClient trusts ca, or the system roots when ca is empty.
func HTTPClient(ca string) (*http.Client, error) {
	roots, err := loadCA(ca)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}, nil
}

func loadCA(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return pool, nil
}

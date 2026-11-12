// Package connect is the connector: it gets database tokens (browser login or a token file) and
// forwards local Postgres connections to pgauth with a fresh token as the password.
package connect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

type Options struct {
	Issuer   string
	ClientID string
	// Resource is sent as the RFC 8707 resource parameter and becomes the token's audience.
	Resource string
	Scope    string
	// Server is pgauth's host:port; ServerCA is a PEM file to trust instead of the system roots.
	Server   string
	ServerCA string
	// CallbackPort is the loopback port of the login redirect; 0 picks a free one (RFC 8252).
	CallbackPort int
	// OpenBrowser opens the login URL; the URL is also logged in case it fails.
	OpenBrowser func(url string) error
	Store       TokenStore
	// StoreKey names the refresh token in Store; default: issuer, client and resource.
	StoreKey string
}

// TokenStore keeps the refresh token between runs.
type TokenStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

// Keychain stores tokens in the OS keychain (macOS Keychain, Secret Service on Linux).
type Keychain struct{}

func (Keychain) Get(key string) (string, error) { return keyring.Get("pgauth", key) }
func (Keychain) Set(key, value string) error    { return keyring.Set("pgauth", key, value) }
func (Keychain) Delete(key string) error {
	if err := keyring.Delete("pgauth", key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

type Connector struct {
	opts Options
	tls  *tls.Config
	log  *slog.Logger

	mu        sync.Mutex
	disc      *discovery
	access    string
	accessExp time.Time
	refreshed string
}

// accessMargin is how long a cached access token must still be valid; pgauth checks it only at connect.
const accessMargin = 30 * time.Second

func New(opts Options, log *slog.Logger) (*Connector, error) {
	host, _, err := net.SplitHostPort(opts.Server)
	if err != nil {
		return nil, fmt.Errorf("server %q: %w", opts.Server, err)
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if opts.ServerCA != "" {
		pem, err := os.ReadFile(opts.ServerCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", opts.ServerCA)
		}
		tlsCfg.RootCAs = pool
	}
	return &Connector{opts: opts, tls: tlsCfg, log: log}, nil
}

func (c *Connector) storeKey() string {
	if c.opts.StoreKey != "" {
		return c.opts.StoreKey
	}
	return c.opts.Issuer + " " + c.opts.ClientID + " " + c.opts.Resource
}

// Login runs the browser login now, ignoring any stored refresh token, and keeps its tokens.
func (c *Connector) Login(ctx context.Context) error {
	c.mu.Lock()
	c.access, c.refreshed = "", ""
	c.mu.Unlock()
	if err := c.opts.Store.Delete(c.storeKey()); err != nil {
		c.log.Warn("could not clear the stored refresh token", "error", err)
	}
	_, err := c.Token(ctx)
	return err
}

// Token returns a database token valid for at least accessMargin, refreshing or logging in as needed.
func (c *Connector) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access != "" && time.Until(c.accessExp) > accessMargin {
		return c.access, nil
	}
	if c.disc == nil {
		d, err := discover(ctx, c.opts.Issuer)
		if err != nil {
			return "", err
		}
		c.disc = d
	}
	refreshToken := c.refreshed
	if refreshToken == "" {
		refreshToken, _ = c.opts.Store.Get(c.storeKey())
	}
	var tok *tokenResponse
	var err error
	if refreshToken != "" {
		tok, err = c.refresh(ctx, c.disc, refreshToken)
		if err != nil {
			c.log.Info("refresh failed, logging in again", "error", err)
		}
	}
	if tok == nil {
		if tok, err = c.login(ctx, c.disc); err != nil {
			return "", err
		}
	}
	c.access = tok.AccessToken
	c.accessExp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	if tok.RefreshToken != "" {
		c.refreshed = tok.RefreshToken
		if err := c.opts.Store.Set(c.storeKey(), tok.RefreshToken); err != nil {
			c.log.Warn("could not save the refresh token; you will log in again next run", "error", err)
		}
	}
	return c.access, nil
}

// Listener is one local address; with an Instance, bare database names are taken to be on it.
type Listener struct {
	Listen   string `json:"listen"`
	Instance string `json:"instance"`
}

// TargetDatabase is the database pgauth is asked for: a bare name gets "<instance>/" when the
// listener names an instance, anything else passes through.
func TargetDatabase(instance, db string) string {
	if instance == "" || db == "" || strings.Contains(db, "/") {
		return db
	}
	return instance + "/" + db
}

// ServeAll listens on every listener and serves them with this Connector's one token until ctx
// ends or a listener fails.
func (c *Connector) ServeAll(ctx context.Context, listeners []Listener) error {
	lns := make([]net.Listener, 0, len(listeners))
	defer func() {
		for _, ln := range lns {
			ln.Close()
		}
	}()
	for _, l := range listeners {
		ln, err := net.Listen("tcp", l.Listen)
		if err != nil {
			return err
		}
		lns = append(lns, ln)
		host, port, _ := net.SplitHostPort(ln.Addr().String())
		db := "<instance>/<db>"
		if l.Instance != "" {
			db = "<db>"
		}
		c.log.Info("ready", "instance", l.Instance, "connect", fmt.Sprintf(`psql "host=%s port=%s dbname=%s"`, host, port, db))
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(lns))
	for i, ln := range lns {
		go func() { errs <- c.Serve(ctx, ln, listeners[i].Instance) }()
	}
	err := <-errs
	cancel()
	for range len(lns) - 1 {
		<-errs
	}
	return err
}

// Serve accepts local connections on ln until ctx ends; instance is the listener's instance, if any.
func (c *Connector) Serve(ctx context.Context, ln net.Listener, instance string) error {
	up := &upstream{server: c.opts.Server, tls: c.tls, tokens: c}
	f := &forwarder{log: c.log, route: func(_ context.Context, db string) (target, error) {
		t := target{up: up, database: TargetDatabase(instance, db), label: db}
		return t, nil
	}}
	return f.serve(ctx, ln)
}

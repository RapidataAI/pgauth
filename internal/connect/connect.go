// Package connect is the connector: it logs a person in through the browser and forwards local
// Postgres connections to pgauth with a fresh database token as the password.
package connect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
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
	Listen   string
	// OpenBrowser opens the login URL; the URL is also logged in case it fails.
	OpenBrowser func(url string) error
	Store       TokenStore
}

// TokenStore keeps the refresh token between runs.
type TokenStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
}

// Keychain stores tokens in the OS keychain (macOS Keychain, Secret Service on Linux).
type Keychain struct{}

func (Keychain) Get(key string) (string, error) { return keyring.Get("pgauth", key) }
func (Keychain) Set(key, value string) error    { return keyring.Set("pgauth", key, value) }

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
	return c.opts.Issuer + " " + c.opts.ClientID + " " + c.opts.Resource
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

// Serve accepts local connections until ctx ends.
func (c *Connector) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.handle(ctx, conn)
		}()
	}
}

func (c *Connector) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	backend := pgproto3.NewBackend(conn, conn)
	var startup *pgproto3.StartupMessage
	for startup == nil {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg := msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.CancelRequest:
			c.forwardCancel(ctx, msg)
			return
		case *pgproto3.StartupMessage:
			startup = msg
		}
	}

	token, err := c.Token(ctx)
	if err != nil {
		c.log.Error("no database token", "error", err)
		fail(backend, "28000", "pgauth connect: "+err.Error())
		return
	}
	up, err := c.dial(ctx)
	if err != nil {
		c.log.Error("dial pgauth", "server", c.opts.Server, "error", err)
		fail(backend, "08001", "pgauth connect: cannot reach "+c.opts.Server)
		return
	}
	defer up.Close()
	frontend := pgproto3.NewFrontend(up, up)
	frontend.Send(startup)
	if err := frontend.Flush(); err != nil {
		return
	}
	msg, err := frontend.Receive()
	if err != nil {
		fail(backend, "08006", "pgauth connect: pgauth closed the connection")
		return
	}
	switch msg := msg.(type) {
	case *pgproto3.AuthenticationCleartextPassword:
	case *pgproto3.ErrorResponse:
		backend.Send(msg)
		_ = backend.Flush()
		return
	default:
		fail(backend, "08P01", fmt.Sprintf("pgauth connect: unexpected %T from pgauth", msg))
		return
	}
	frontend.Send(&pgproto3.PasswordMessage{Password: token})
	if err := frontend.Flush(); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	splice(conn, up)
}

func (c *Connector) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.opts.Server)
	if err != nil {
		return nil, err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(d)
	}
	buf, _ := (&pgproto3.SSLRequest{}).Encode(nil)
	if _, err := raw.Write(buf); err != nil {
		raw.Close()
		return nil, err
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(raw, resp); err != nil {
		raw.Close()
		return nil, err
	}
	if resp[0] != 'S' {
		raw.Close()
		return nil, errors.New("pgauth refused TLS")
	}
	conn := tls.Client(raw, c.tls)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

func (c *Connector) forwardCancel(ctx context.Context, req *pgproto3.CancelRequest) {
	up, err := c.dial(ctx)
	if err != nil {
		return
	}
	defer up.Close()
	buf, _ := req.Encode(nil)
	_, _ = up.Write(buf)
}

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func fail(backend *pgproto3.Backend, code, msg string) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: code, Message: msg})
	_ = backend.Flush()
}

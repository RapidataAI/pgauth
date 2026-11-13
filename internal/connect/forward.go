package connect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// TokenSource hands out a database token for one connection.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// upstream is one pgauth server and where its tokens come from.
type upstream struct {
	server string
	tls    *tls.Config
	tokens TokenSource
}

// target is where one client connection goes: database is what pgauth is asked for, label what
// the client asked for, used in messages.
type target struct {
	up       *upstream
	database string
	label    string
}

// routeError is a refusal shown to the client as a FATAL with its own message.
type routeError struct{ msg string }

func (e routeError) Error() string { return e.msg }

type forwarder struct {
	log   *slog.Logger
	route func(ctx context.Context, database string) (target, error)
	// keys maps pgauth's cancel key of each open connection to its upstream.
	keys sync.Map
}

type cancelKey struct {
	secret []byte
	up     *upstream
}

func (f *forwarder) serve(ctx context.Context, ln net.Listener) error {
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
		wg.Go(func() { f.handle(ctx, conn) })
	}
}

func (f *forwarder) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	backend := pgproto3.NewBackend(conn, conn)
	backend.SetMaxBodyLen(64 << 10)
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
			f.forwardCancel(ctx, msg)
			return
		case *pgproto3.StartupMessage:
			startup = msg
		}
	}

	asked := startup.Parameters["database"]
	t, err := f.route(ctx, asked)
	if err != nil {
		f.log.Info("connection refused", "database", asked, "reason", err)
		fail(backend, "3D000", "pgauth connect: "+err.Error())
		return
	}
	if t.database != asked {
		f.log.Info("connection", "database", asked+" → "+t.database)
	} else {
		f.log.Info("connection", "database", asked)
	}
	startup.Parameters["database"] = t.database

	tok, err := t.up.tokens.Token(ctx)
	if err != nil {
		f.log.Error("no database token", "database", asked, "error", err)
		fail(backend, "28000", "pgauth connect: "+err.Error())
		return
	}
	up, err := dial(ctx, t.up)
	if err != nil {
		f.log.Error("dial pgauth", "server", t.up.server, "error", err)
		fail(backend, "08001", "pgauth connect: cannot reach "+t.up.server)
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
		f.relayError(backend, msg)
		return
	default:
		fail(backend, "08P01", fmt.Sprintf("pgauth connect: unexpected %T from pgauth", msg))
		return
	}
	frontend.Send(&pgproto3.PasswordMessage{Password: tok})
	if err := frontend.Flush(); err != nil {
		return
	}
	// Relay the startup answers message by message up to ReadyForQuery, so the cancel key is known;
	// after that the server is silent until the client speaks.
	var key uint32
	defer func() {
		if key != 0 {
			f.keys.Delete(key)
		}
	}()
	for {
		msg, err := frontend.Receive()
		if err != nil {
			fail(backend, "08006", "pgauth connect: pgauth closed the connection")
			return
		}
		switch msg := msg.(type) {
		case *pgproto3.ErrorResponse:
			f.relayError(backend, msg)
			return
		case *pgproto3.BackendKeyData:
			key = msg.ProcessID
			f.keys.Store(key, cancelKey{secret: append([]byte(nil), msg.SecretKey...), up: t.up})
			backend.Send(msg)
		case *pgproto3.ReadyForQuery:
			backend.Send(msg)
			if err := backend.Flush(); err != nil {
				return
			}
			_ = conn.SetDeadline(time.Time{})
			splice(conn, up)
			return
		default:
			backend.Send(msg)
		}
	}
}

// relayError passes pgauth's refusal on unchanged: serve's text says why and where to ask.
func (f *forwarder) relayError(backend *pgproto3.Backend, msg *pgproto3.ErrorResponse) {
	backend.Send(msg)
	_ = backend.Flush()
}

func (f *forwarder) forwardCancel(ctx context.Context, req *pgproto3.CancelRequest) {
	v, ok := f.keys.Load(req.ProcessID)
	if !ok {
		return
	}
	up, err := dial(ctx, v.(cancelKey).up)
	if err != nil {
		return
	}
	defer up.Close()
	buf, _ := req.Encode(nil)
	_, _ = up.Write(buf)
}

func dial(ctx context.Context, u *upstream) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", u.server)
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
	conn := tls.Client(raw, u.tls)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
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

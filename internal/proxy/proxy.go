// Package proxy accepts Postgres connections whose password is a database token, logs in upstream as
// a temporary role carrying the token's rights, and splices bytes between the two.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/RapidataAI/pgauth/internal/config"
	"github.com/RapidataAI/pgauth/internal/rbac"
	"github.com/RapidataAI/pgauth/internal/roles"
	"github.com/RapidataAI/pgauth/internal/token"
)

const handshakeTimeout = 30 * time.Second

type Server struct {
	cfg      *config.Config
	verifier *token.Verifier
	rbac     *rbac.Store
	tls      *tls.Config
	log      *slog.Logger
	tracer   trace.Tracer

	instances map[string]*instance
	cancels   sync.Map // uint32 client-facing pid -> *cancelTarget
	conns     sync.WaitGroup
	stopping  chan struct{}
}

type instance struct {
	cfg   config.Instance
	ready atomic.Bool
	pool  *pgxpool.Pool
	roles *roles.Manager
}

type cancelTarget struct {
	secret   []byte
	upstream *pgconn.HijackedConn
}

func New(cfg *config.Config, verifier *token.Verifier, store *rbac.Store, tlsConfig *tls.Config, log *slog.Logger) *Server {
	s := &Server{
		cfg:       cfg,
		verifier:  verifier,
		rbac:      store,
		tls:       tlsConfig,
		log:       log,
		tracer:    otel.Tracer("github.com/RapidataAI/pgauth"),
		instances: map[string]*instance{},
		stopping:  make(chan struct{}),
	}
	for _, in := range cfg.Instances {
		s.instances[in.Name] = &instance{cfg: in}
	}
	return s
}

// Start connects to every instance as the issuer and sweeps leftover temporary roles, retrying
// until each succeeds; connections to an instance are refused until then.
func (s *Server) Start(ctx context.Context) {
	for _, in := range s.instances {
		go func() {
			for wait := time.Second; ; wait = min(2*wait, 30*time.Second) {
				err := s.startInstance(ctx, in)
				if err == nil {
					return
				}
				s.log.Warn("instance not ready", "instance", in.cfg.Name, "error", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}()
	}
}

func (s *Server) startInstance(ctx context.Context, in *instance) error {
	creds, err := in.cfg.Credentials()
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, in.cfg.ConnString(creds.Username, creds.Password, in.cfg.AdminDatabase))
	if err != nil {
		return err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return err
	}
	mgr := roles.NewManager(pool, s.cfg.TempGroup, s.cfg.RolePrefix, []byte(creds.Password), s.log)
	dropped, err := mgr.Sweep(ctx, time.Duration(s.cfg.SweepMinAge))
	if err != nil {
		pool.Close()
		return fmt.Errorf("sweep: %w", err)
	}
	s.log.Info("instance ready", "instance", in.cfg.Name, "swept", dropped)
	in.pool, in.roles = pool, mgr
	in.ready.Store(true)
	return nil
}

// Ready reports whether the issuer's keys and a valid set of access rules are loaded and every
// instance accepts the issuer login.
func (s *Server) Ready(ctx context.Context) error {
	if !s.verifier.Ready() {
		return errors.New("oidc keys not loaded")
	}
	if st := s.rbac.Status(); !st.Loaded {
		if st.Rejected != nil {
			return fmt.Errorf("no valid access rules loaded: %w", st.Rejected)
		}
		return errors.New("access rules not loaded")
	}
	for name, in := range s.instances {
		if !in.ready.Load() {
			return fmt.Errorf("instance %s not ready", name)
		}
		if err := in.pool.Ping(ctx); err != nil {
			return fmt.Errorf("instance %s: %w", name, err)
		}
	}
	return nil
}

// Serve accepts connections until ctx ends, then closes the open ones so their roles are dropped.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		close(s.stopping)
		ln.Close()
	}()
	defer s.conns.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(raw net.Conn) {
	conn := raw
	defer func() { conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	backend := pgproto3.NewBackend(conn, conn)

	for range 3 {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg := msg.(type) {
		case *pgproto3.SSLRequest:
			if conn != raw {
				return
			}
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return
			}
			tlsConn := tls.Server(conn, s.tls)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			backend = pgproto3.NewBackend(conn, conn)
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.CancelRequest:
			s.cancel(msg)
			return
		case *pgproto3.StartupMessage:
			if conn == raw {
				fail(backend, "28000", "pgauth requires TLS: connect with sslmode=require or stricter")
				return
			}
			s.connect(conn, backend, msg)
			return
		}
	}
}

// attempt collects what one connection attempt logs and records on its span.
type attempt struct {
	sub, user, clientID, instance, db, role string
	groups, bindings                        []string
	granted, level, scopeCap                string
}

func (s *Server) connect(conn net.Conn, backend *pgproto3.Backend, startup *pgproto3.StartupMessage) {
	start := time.Now()
	ctx, span := s.tracer.Start(context.Background(), "pgauth.connect", trace.WithSpanKind(trace.SpanKindServer))
	var a attempt
	finish := func(decision, reason string) {
		d := time.Since(start)
		span.SetAttributes(
			attribute.String("pgauth.sub", a.sub),
			attribute.String("pgauth.user", a.user),
			attribute.StringSlice("pgauth.groups", a.groups),
			attribute.String("pgauth.client_id", a.clientID),
			attribute.String("pgauth.instance", a.instance),
			attribute.String("db.namespace", a.db),
			attribute.StringSlice("pgauth.bindings", a.bindings),
			attribute.String("pgauth.granted", a.granted),
			attribute.String("pgauth.level", a.level),
			attribute.String("pgauth.scope_cap", a.scopeCap),
			attribute.String("pgauth.decision", decision),
			attribute.String("pgauth.reason", reason),
			attribute.String("pgauth.role", a.role),
		)
		if decision != "allow" {
			span.SetStatus(codes.Error, reason)
		}
		span.End()
		s.log.InfoContext(ctx, "connect", "sub", a.sub, "user", a.user, "groups", a.groups, "client_id", a.clientID,
			"instance", a.instance, "db", a.db, "bindings", a.bindings, "granted", a.granted, "level", a.level, "scope_cap", a.scopeCap,
			"decision", decision, "reason", reason, "role", a.role, "duration_ms", d.Milliseconds())
	}

	var dbOK bool
	a.instance, a.db, dbOK = strings.Cut(startup.Parameters["database"], "/")
	if !dbOK {
		a.instance, a.db = "", startup.Parameters["database"]
		finish("deny", "database must be <instance>/<db>")
		fail(backend, "3D000", `pgauth: database must be "<instance>/<db>"`)
		return
	}

	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		finish("deny", "client went away")
		return
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		finish("deny", err.Error())
		return
	}
	msg, err := backend.Receive()
	if err != nil {
		finish("deny", "no password")
		return
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		finish("deny", "no password")
		fail(backend, "28000", "pgauth: expected a password message")
		return
	}

	claims, err := s.verifier.Verify(ctx, pw.Password)
	if err != nil {
		finish("deny", err.Error())
		fail(backend, "28P01", "pgauth: "+err.Error())
		return
	}
	a.sub, a.user, a.groups, a.clientID = claims.Subject, claims.Username, claims.Groups, claims.ClientID

	in, d, reason := s.authorize(claims, a.instance, a.db)
	a.bindings, a.granted, a.level, a.scopeCap = d.bindings, d.granted.String(), d.level.String(), d.scopeCap.String()
	if reason != "" {
		finish("deny", reason)
		fail(backend, "28000", "pgauth: "+reason)
		return
	}

	spec := roles.Spec{
		Subject: claims.Subject, Username: claims.Username, ClientID: claims.ClientID,
		Roles: []string{a.instance + "/" + a.db + ":" + d.level.String()}, Groups: d.groupRoles,
	}
	var upstream *pgconn.HijackedConn
	role, pid, err := in.roles.Acquire(ctx, spec, func(role, password string) (uint32, error) {
		up, err := s.dial(ctx, in.cfg, role, password, a.db, startup.Parameters)
		if err != nil {
			return 0, err
		}
		upstream = up
		return up.PID, nil
	})
	a.role = role
	if err != nil {
		finish("error", err.Error())
		fail(backend, "08006", "pgauth: could not open the upstream connection")
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		in.roles.Release(ctx, role, pid)
	}()
	defer upstream.Conn.Close()

	clientPID, err := s.greet(backend, startup, upstream)
	if err != nil {
		finish("error", "client went away")
		return
	}
	defer s.cancels.Delete(clientPID)
	finish("allow", "")

	_ = conn.SetDeadline(time.Time{})
	splice(conn, upstream.Conn, time.Duration(s.cfg.MaxConnectionAge), s.stopping)
}

type decision struct {
	bindings   []string
	granted    rbac.Level // from the bindings, before the scope cap
	level      rbac.Level // after the scope cap
	scopeCap   rbac.Level
	groupRoles []string
}

// authorize decides the access level on instance/db from the role bindings, capped by the token's
// scope, or returns a reason to deny.
func (s *Server) authorize(claims token.Claims, instName, db string) (*instance, decision, string) {
	var d decision
	in, ok := s.instances[instName]
	if !ok {
		return nil, d, fmt.Sprintf("unknown instance %q", instName)
	}
	if !in.cfg.Serves(db) {
		return nil, d, fmt.Sprintf("database %s/%s is not served", instName, db)
	}
	if !in.ready.Load() {
		return nil, d, fmt.Sprintf("instance %s is not ready", instName)
	}
	policy := s.rbac.Policy()
	if policy == nil {
		return nil, d, "access rules are not loaded"
	}
	who := rbac.Who{User: claims.Username, Groups: claims.Groups, FoldUser: s.cfg.OIDC.FoldUsername()}
	d.granted, d.bindings = policy.Access(who, instName, db)
	d.scopeCap = rbac.ScopeCap(claims.Scopes, s.cfg.OIDC.Scopes.Read, s.cfg.OIDC.Scopes.Write)
	d.level = min(d.granted, d.scopeCap)
	switch {
	case d.granted == rbac.None:
		return nil, d, fmt.Sprintf("no role binding grants %s access to %s/%s", claims.Username, instName, db)
	case d.scopeCap == rbac.None:
		return nil, d, fmt.Sprintf("token has neither the %s nor the %s scope", s.cfg.OIDC.Scopes.Read, s.cfg.OIDC.Scopes.Write)
	}
	d.groupRoles = []string{s.cfg.GroupRole("read", db)}
	if d.level == rbac.Write {
		d.groupRoles = append(d.groupRoles, s.cfg.GroupRole("write", db))
	}
	return in, d, ""
}

func (s *Server) dial(ctx context.Context, in config.Instance, role, password, db string, params map[string]string) (*pgconn.HijackedConn, error) {
	cfg, err := pgconn.ParseConfig(in.ConnString(role, password, db))
	if err != nil {
		return nil, err
	}
	cfg.MinProtocolVersion, cfg.MaxProtocolVersion = "3.0", "3.0"
	for k, v := range params {
		if k == "user" || k == "database" || k == "replication" || strings.HasPrefix(k, "_pq_.") {
			continue
		}
		cfg.RuntimeParams[k] = v
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	pc, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pc.SyncConn(ctx); err != nil {
		pc.Close(ctx)
		return nil, err
	}
	return pc.Hijack()
}

// greet finishes the client's startup as if it had logged in directly, with a cancel key of pgauth's own.
func (s *Server) greet(backend *pgproto3.Backend, startup *pgproto3.StartupMessage, up *pgconn.HijackedConn) (uint32, error) {
	var unknown []string
	for k := range startup.Parameters {
		if strings.HasPrefix(k, "_pq_.") {
			unknown = append(unknown, k)
		}
	}
	if startup.ProtocolVersion != pgproto3.ProtocolVersion30 || len(unknown) > 0 {
		backend.Send(&pgproto3.NegotiateProtocolVersion{NewestMinorProtocol: 0, UnrecognizedOptions: unknown})
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	for k, v := range up.ParameterStatuses {
		backend.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}
	key := make([]byte, 8)
	_, _ = rand.Read(key)
	pid := binary.BigEndian.Uint32(key[:4]) &^ (1 << 31)
	for {
		if _, loaded := s.cancels.LoadOrStore(pid, &cancelTarget{secret: key[4:], upstream: up}); !loaded {
			break
		}
		pid++
	}
	backend.Send(&pgproto3.BackendKeyData{ProcessID: pid, SecretKey: key[4:]})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: up.TxStatus})
	if err := backend.Flush(); err != nil {
		s.cancels.Delete(pid)
		return 0, err
	}
	return pid, nil
}

// cancel forwards a cancel request to the upstream backend it was issued for.
func (s *Server) cancel(req *pgproto3.CancelRequest) {
	v, ok := s.cancels.Load(req.ProcessID)
	if !ok {
		return
	}
	t := v.(*cancelTarget)
	if subtle.ConstantTimeCompare(t.secret, req.SecretKey) != 1 {
		return
	}
	cfg := t.upstream.Config
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	if err != nil {
		s.log.Warn("cancel request", "error", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if t.upstream.TLSConfig != nil {
		buf, _ := (&pgproto3.SSLRequest{}).Encode(nil)
		if _, err := conn.Write(buf); err != nil {
			return
		}
		resp := make([]byte, 1)
		if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != 'S' {
			return
		}
		tlsConn := tls.Client(conn, t.upstream.TLSConfig)
		defer tlsConn.Close()
		conn = tlsConn
	}
	buf, _ := (&pgproto3.CancelRequest{ProcessID: t.upstream.PID, SecretKey: t.upstream.SecretKey}).Encode(nil)
	_, _ = conn.Write(buf)
}

// splice copies bytes both ways until either side closes, maxAge passes or stop closes.
func splice(client, upstream net.Conn, maxAge time.Duration, stop <-chan struct{}) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(upstream, client)
	go cp(client, upstream)
	timer := time.NewTimer(maxAge)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-stop:
	}
	client.Close()
	upstream.Close()
	<-done
}

func fail(backend *pgproto3.Backend, code, msg string) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: code, Message: msg})
	_ = backend.Flush()
}

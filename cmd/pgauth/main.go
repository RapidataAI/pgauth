// Command pgauth is a Postgres proxy that accepts a short-lived OIDC token as the password.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/RapidataAI/pgauth/internal/api"
	"github.com/RapidataAI/pgauth/internal/config"
	"github.com/RapidataAI/pgauth/internal/proxy"
	"github.com/RapidataAI/pgauth/internal/rbac"
	"github.com/RapidataAI/pgauth/internal/telemetry"
	"github.com/RapidataAI/pgauth/internal/token"
)

var version = "dev"

const usage = `pgauth: Postgres access with short-lived OIDC tokens

Usage:
  pgauth serve --config <file>          run the proxy
  pgauth lint [--config <file>] <dir>   check the PgRole / PgRoleBinding YAML in <dir>
  pgauth connect [flags]                log in through the browser and serve localhost for Postgres clients
  pgauth version                 print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "lint":
		os.Exit(lint(os.Args[2:]))
	case "connect":
		err = connectCmd(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgauth:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "/etc/pgauth/config.yaml", "path to the config file")
	_ = fs.Parse(args)

	log := telemetry.Logger(os.Stdout, nil)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTelemetry, logs, err := telemetry.Setup(ctx)
	if err != nil {
		return err
	}
	defer shutdownTelemetry()
	log = telemetry.Logger(os.Stdout, logs)

	certs := &certReloader{certFile: cfg.TLS.CertFile, keyFile: cfg.TLS.KeyFile}
	if _, err := certs.get(nil); err != nil {
		return err
	}
	verifier := token.NewVerifier(cfg.OIDC)
	go verifier.Start(ctx, log)
	store, err := rbacStore(cfg, log)
	if err != nil {
		return err
	}
	go store.WatchDir(ctx, cfg.RBAC.Dir, time.Duration(cfg.RBAC.ReloadInterval))
	tlsConfig := &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12}
	srv := proxy.New(cfg, verifier, store, tlsConfig, log)
	srv.Start(ctx)

	if cfg.Health != "" {
		go serveHealth(ctx, cfg.Health, srv, store, log)
	}
	if cfg.HTTP.Listen != "" {
		hs := &http.Server{Addr: cfg.HTTP.Listen, Handler: api.New(cfg, verifier, store).Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			<-ctx.Done()
			_ = hs.Close()
		}()
		go func() {
			if err := hs.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("https server", "error", err)
				stop()
			}
		}()
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("pgauth listening", "addr", cfg.Listen, "version", version)
	return srv.Serve(ctx, ln)
}

// rbacStore records every load of the access rules as metrics: a counter by result and a gauge
// that is 1 while the last change was rejected.
func rbacStore(cfg *config.Config, log *slog.Logger) (*rbac.Store, error) {
	meter := otel.Meter("github.com/RapidataAI/pgauth")
	loads, err := meter.Int64Counter("pgauth.rbac.loads", metric.WithDescription("Access-rule loads by result"))
	if err != nil {
		return nil, err
	}
	rejected, err := meter.Int64Gauge("pgauth.rbac.rejected", metric.WithDescription("1 while the last access-rule change was rejected"))
	if err != nil {
		return nil, err
	}
	store := rbac.NewStore(cfg.Databases(), log)
	store.OnLoad = func(err error) {
		ctx := context.Background()
		if err != nil {
			loads.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "rejected")))
			rejected.Record(ctx, 1)
			return
		}
		loads.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "ok")))
		rejected.Record(ctx, 0)
	}
	return store, nil
}

func serveHealth(ctx context.Context, addr string, srv *proxy.Server, store *rbac.Store, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := srv.Ready(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
		if st := store.Status(); st.Rejected != nil {
			fmt.Fprintf(w, "access rules: change rejected at %s, still serving the set loaded at %s:\n%v\n",
				st.RejectedAt.Format(time.RFC3339), st.LoadedAt.Format(time.RFC3339), st.Rejected)
		}
	})
	hs := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = hs.Close()
	}()
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("health server", "error", err)
	}
}

// certReloader rereads the certificate when its file changes, so a renewed certificate needs no restart.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	mod               time.Time
	cert              *tls.Certificate
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(c.certFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert == nil || !st.ModTime().Equal(c.mod) {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			if c.cert != nil {
				return c.cert, nil
			}
			return nil, err
		}
		c.cert, c.mod = &cert, st.ModTime()
	}
	return c.cert, nil
}

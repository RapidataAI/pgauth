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

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/RapidataAI/pgauth/internal/config"
	"github.com/RapidataAI/pgauth/internal/proxy"
	"github.com/RapidataAI/pgauth/internal/token"
)

var version = "dev"

const usage = `pgauth: Postgres access with short-lived OIDC tokens

Usage:
  pgauth serve --config <file>   run the proxy
  pgauth connect [flags]         log in through the browser and serve localhost for Postgres clients
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

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := setupTracing(ctx)
	if err != nil {
		return err
	}
	defer shutdownTracing()

	certs := &certReloader{certFile: cfg.TLS.CertFile, keyFile: cfg.TLS.KeyFile}
	if _, err := certs.get(nil); err != nil {
		return err
	}
	verifier := token.NewVerifier(cfg.OIDC)
	go verifier.Start(ctx, log)
	srv := proxy.New(cfg, verifier, &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12}, log)
	srv.Start(ctx)

	if cfg.Health != "" {
		go serveHealth(ctx, cfg.Health, srv, log)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("pgauth listening", "addr", cfg.Listen, "version", version)
	return srv.Serve(ctx, ln)
}

func serveHealth(ctx context.Context, addr string, srv *proxy.Server, log *slog.Logger) {
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

// setupTracing exports spans only when an OTLP endpoint is configured through the standard env vars.
func setupTracing(ctx context.Context) (func(), error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return func() {}, nil
	}
	exp, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return nil, err
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attribute.String("service.name", "pgauth")))
	if err != nil {
		return nil, err
	}
	res, err = resource.Merge(res, resource.Environment())
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tp.Shutdown(ctx)
	}, nil
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

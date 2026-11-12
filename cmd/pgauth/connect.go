package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"sigs.k8s.io/yaml"

	"github.com/RapidataAI/pgauth/internal/connect"
)

// connectFile holds defaults for `pgauth connect`; flags override it.
type connectFile struct {
	Issuer    string             `json:"issuer"`
	ClientID  string             `json:"clientId"`
	Resource  string             `json:"resource"`
	Scope     string             `json:"scope"`
	Server    string             `json:"server"`
	ServerCA  string             `json:"serverCA"`
	Listen    string             `json:"listen"`
	Listeners []connect.Listener `json:"listeners"`
	// CallbackPort is a pointer so an explicit 0 (random port) differs from unset.
	CallbackPort *int `json:"callbackPort"`
}

func connectCmd(args []string) error {
	defaultPath := ""
	if dir, err := os.UserConfigDir(); err == nil {
		defaultPath = filepath.Join(dir, "pgauth", "connect.yaml")
	}
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	path := fs.String("config", defaultPath, "YAML file with defaults for the flags below")
	issuer := fs.String("issuer", "", "OIDC issuer URL")
	clientID := fs.String("client-id", "", "public OIDC client id")
	resource := fs.String("resource", "", "resource (audience) the database token is for")
	scope := fs.String("scope", "", `scopes to request (default "openid offline_access")`)
	server := fs.String("server", "", "pgauth address, host:port")
	serverCA := fs.String("server-ca", "", "PEM file with the CA that signed pgauth's certificate (default: system roots)")
	listen := fs.String("listen", "", `local address Postgres clients connect to; replaces the config's listeners (default "127.0.0.1:5432")`)
	instance := fs.String("instance", "", "with --listen: instance that bare database names are on")
	callbackPort := fs.Int("callback-port", defaultCallbackPort, "loopback port of the login redirect http://127.0.0.1:<port>/callback; 0 picks a free port")
	_ = fs.Parse(args)

	var f connectFile
	if b, err := os.ReadFile(*path); err == nil {
		if err := yaml.UnmarshalStrict(b, &f); err != nil {
			return fmt.Errorf("parse %s: %w", *path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pick := func(flagV, fileV, def string) string {
		if flagV != "" {
			return flagV
		}
		if fileV != "" {
			return fileV
		}
		return def
	}
	opts := connect.Options{
		Issuer:       pick(*issuer, f.Issuer, ""),
		ClientID:     pick(*clientID, f.ClientID, ""),
		Resource:     pick(*resource, f.Resource, ""),
		Scope:        pick(*scope, f.Scope, "openid offline_access"),
		Server:       pick(*server, f.Server, ""),
		ServerCA:     pick(*serverCA, f.ServerCA, ""),
		CallbackPort: *callbackPort,
		OpenBrowser:  openBrowser,
		Store:        connect.Keychain{},
	}
	if f.CallbackPort != nil && !flagSet(fs, "callback-port") {
		opts.CallbackPort = *f.CallbackPort
	}
	if opts.Issuer == "" || opts.ClientID == "" || opts.Server == "" {
		return fmt.Errorf("--issuer, --client-id and --server are required (or set them in %s)", *path)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c, err := connect.New(opts, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if _, err := c.Token(ctx); err != nil {
		return err
	}
	return c.ServeAll(ctx, listeners(*listen, *instance, f))
}

const defaultCallbackPort = 8250

// listeners: --listen replaces the file's; otherwise the file's listeners plus its top-level listen,
// which has no instance; with neither, 127.0.0.1:5432.
func listeners(flagListen, flagInstance string, f connectFile) []connect.Listener {
	if flagListen != "" {
		return []connect.Listener{{Listen: flagListen, Instance: flagInstance}}
	}
	out := append([]connect.Listener(nil), f.Listeners...)
	if f.Listen != "" {
		out = append(out, connect.Listener{Listen: f.Listen})
	}
	if len(out) == 0 {
		out = append(out, connect.Listener{Listen: "127.0.0.1:5432", Instance: flagInstance})
	}
	return out
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

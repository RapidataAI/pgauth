package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/RapidataAI/pgauth/internal/api"
	"github.com/RapidataAI/pgauth/internal/connect"
)

const defaultCallbackPort = 8250

// configPath picks connect.yaml: --config, then $PGAUTH_CONFIG, then the user config directory.
func configPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("PGAUTH_CONFIG"); env != "" {
		return env
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "pgauth", "connect.yaml")
	}
	return "connect.yaml"
}

// parseInterspersed lets flags follow positional arguments, as in `env add prod host --write`.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func newLog() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

func connectCmd(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml (default $PGAUTH_CONFIG, else the user config directory)")
	listen := fs.String("listen", "", `local address Postgres clients connect to (default "127.0.0.1:5432")`)
	callbackPort := fs.Int("callback-port", defaultCallbackPort, "loopback port of the login redirect; 0 picks a free port")
	// v0.4 flags: a single server without environments.
	issuer := fs.String("issuer", "", "deprecated (v0.4): OIDC issuer URL")
	clientID := fs.String("client-id", "", "deprecated (v0.4): public OIDC client id")
	resource := fs.String("resource", "", "deprecated (v0.4): resource (audience) of the token")
	scope := fs.String("scope", "", "deprecated (v0.4): scopes to request")
	server := fs.String("server", "", "deprecated (v0.4): pgauth address, host:port")
	serverCA := fs.String("server-ca", "", "PEM file with the CA that signed pgauth's certificate")
	instance := fs.String("instance", "", "deprecated (v0.4): with --listen, the instance bare names are on")
	_ = fs.Parse(args)

	log := newLog()
	f, err := connect.LoadFile(configPath(*path))
	if err != nil {
		return err
	}
	port := *callbackPort
	if f.CallbackPort != nil && !flagSet(fs, "callback-port") {
		port = *f.CallbackPort
	}
	if *serverCA != "" {
		f.ServerCA = *serverCA
	}
	if f.Legacy() || *server != "" || *issuer != "" {
		log.Warn("connect.yaml uses the v0.4 single-server format; it still works in v0.5 and stops in v0.6. Run `pgauth env add <name> <host>` to switch to environments.")
		for flagV, field := range map[*string]*string{issuer: &f.Issuer, clientID: &f.ClientID, resource: &f.Resource, scope: &f.Scope, server: &f.Server} {
			if *flagV != "" {
				*field = *flagV
			}
		}
		return connectLegacy(f, port, *listen, *instance, log)
	}

	if err := f.Validate(); err != nil {
		return err
	}
	envs, err := f.BuildEnvs(connect.BuildOptions{Store: connect.Keychain{}, OpenBrowser: openBrowser, CallbackPort: port, Log: log})
	if err != nil {
		return err
	}
	addr := *listen
	if addr == "" {
		addr = f.Listen
	}
	if addr == "" {
		addr = "127.0.0.1:5432"
	}
	listeners := append([]connect.Listener{{Listen: addr}}, f.Listeners...)
	lns := make([]net.Listener, 0, len(listeners))
	defer func() {
		for _, ln := range lns {
			ln.Close()
		}
	}()
	router := connect.NewRouter(envs, log)
	for _, l := range listeners {
		ln, err := net.Listen("tcp", l.Listen)
		if err != nil {
			return err
		}
		lns = append(lns, ln)
		host, p, _ := net.SplitHostPort(ln.Addr().String())
		if l.Env == "" {
			log.Info("ready", "environments", strings.Join(router.Names(), ","), "connect", fmt.Sprintf(`psql "host=%s port=%s dbname=<env>/<db>"`, host, p))
		} else {
			log.Info("ready", "env", l.Env, "connect", fmt.Sprintf(`psql "host=%s port=%s dbname=<db>"`, host, p))
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, len(lns))
	for i, ln := range lns {
		go func() { errs <- router.Serve(ctx, ln, listeners[i].Env) }()
	}
	err = <-errs
	stop()
	for range len(lns) - 1 {
		<-errs
	}
	return err
}

func connectLegacy(f *connect.File, callbackPort int, listen, instance string, log *slog.Logger) error {
	if f.Scope == "" {
		f.Scope = "openid offline_access"
	}
	if f.Issuer == "" || f.ClientID == "" || f.Server == "" {
		return fmt.Errorf("--issuer, --client-id and --server are required in the v0.4 format")
	}
	c, err := connect.New(connect.Options{
		Issuer: f.Issuer, ClientID: f.ClientID, Resource: f.Resource, Scope: f.Scope, Server: f.Server, ServerCA: f.ServerCA,
		CallbackPort: callbackPort, OpenBrowser: openBrowser, Store: connect.Keychain{},
	}, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if _, err := c.Token(ctx); err != nil {
		return err
	}
	return c.ServeAll(ctx, listeners(listen, instance, f))
}

// listeners (v0.4): --listen replaces the file's; otherwise the file's listeners plus its top-level
// listen, which has no instance; with neither, 127.0.0.1:5432.
func listeners(flagListen, flagInstance string, f *connect.File) []connect.Listener {
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

// loadEnvs reads and validates connect.yaml for the commands that act on environments.
func loadEnvs(path string, log *slog.Logger) (*connect.File, *connect.Router, error) {
	f, err := connect.LoadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, nil, err
	}
	port := defaultCallbackPort
	if f.CallbackPort != nil {
		port = *f.CallbackPort
	}
	envs, err := f.BuildEnvs(connect.BuildOptions{Store: connect.Keychain{}, OpenBrowser: openBrowser, CallbackPort: port, Log: log})
	if err != nil {
		return nil, nil, err
	}
	return f, connect.NewRouter(envs, log), nil
}

func lsCmd(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml")
	pos := parseInterspersed(fs, args)
	_, router, err := loadEnvs(configPath(*path), newLog())
	if err != nil {
		return err
	}
	names := router.Names()
	if len(pos) > 0 {
		if _, ok := router.Env(pos[0]); !ok {
			return fmt.Errorf("no environment %s; environments: %s", pos[0], strings.Join(names, ", "))
		}
		names = pos[:1]
	}
	return printAccess(context.Background(), router, names)
}

func printAccess(ctx context.Context, router *connect.Router, names []string) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DATABASE\tLEVEL")
	failed := false
	for _, name := range names {
		e, _ := router.Env(name)
		d, err := e.Discovery(ctx)
		var access []api.Access
		if err == nil {
			access, err = e.Access(ctx)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			failed = true
			continue
		}
		for _, a := range access {
			fmt.Fprintf(w, "%s\t%s\n", e.Address(d, a.Instance, a.Database), a.Level)
		}
	}
	_ = w.Flush()
	if failed {
		return fmt.Errorf("some environments could not be listed")
	}
	return nil
}

func envCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pgauth env add|list|remove|login")
	}
	fs := flag.NewFlagSet("env "+args[0], flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml")
	ca := fs.String("ca", "", "env add: PEM file with the CA that signed the server's certificate")
	write := fs.Bool("write", false, "env add: ask for the write scope instead of read")
	noLogin := fs.Bool("no-login", false, "env add: do not log in now")
	force := fs.Bool("force", false, "env add: replace an environment whose issuer or token source changed")
	idePort := fs.Int("ide-port", 0, "env add: also listen on 127.0.0.1:<port> for this environment, where bare names work (for IDEs)")
	pos := parseInterspersed(fs, args[1:])
	cfgPath := configPath(*path)
	f, err := connect.LoadFile(cfgPath)
	if err != nil {
		return err
	}
	log := newLog()
	switch args[0] {
	case "add":
		if len(pos) != 2 {
			return fmt.Errorf("usage: pgauth env add <name> <host[:port]> [--ca file] [--write] [--ide-port port] [--no-login] [--force]")
		}
		name, host := pos[0], pos[1]
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, connect.DefaultAPIPort)
		}
		apiURL := "https://" + host
		client, err := connect.HTTPClient(*ca)
		if err != nil {
			return err
		}
		d, err := connect.FetchDiscovery(context.Background(), client, apiURL)
		if err != nil {
			return err
		}
		if err := connect.AddEnv(f, name, apiURL, d, connect.AddOptions{CA: *ca, Write: *write, Force: *force, IDEPort: *idePort}); err != nil {
			return err
		}
		if err := f.Save(cfgPath); err != nil {
			return err
		}
		fmt.Printf("environment %s → %s, issuer %s, written to %s\n", name, d.Postgres, d.Issuer, cfgPath)
		if *noLogin {
			return nil
		}
		return envLogin(cfgPath, name, log)
	case "list":
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSERVER\tTOKEN")
		for _, name := range f.EnvNames() {
			e := f.Environments[name]
			tok := "browser " + e.Token.Issuer
			if e.Token.File != "" {
				tok = "file " + e.Token.File
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", name, e.Server, tok)
		}
		return w.Flush()
	case "remove":
		if len(pos) != 1 || f.Environments[pos[0]] == nil {
			return fmt.Errorf("usage: pgauth env remove <name>; environments: %s", strings.Join(f.EnvNames(), ", "))
		}
		e := f.Environments[pos[0]]
		if e.Token.Login != "" {
			if err := (connect.Keychain{}).Delete(connect.KeychainKey(pos[0], e.Token)); err != nil {
				log.Warn("could not delete the keychain entry", "error", err)
			}
		}
		delete(f.Environments, pos[0])
		f.RemoveListeners(pos[0])
		return f.Save(cfgPath)
	case "login":
		if len(pos) != 1 {
			return fmt.Errorf("usage: pgauth env login <name>")
		}
		return envLogin(cfgPath, pos[0], log)
	default:
		return fmt.Errorf("usage: pgauth env add|list|remove|login")
	}
}

// envLogin logs in to a browser environment afresh and prints what it reaches.
func envLogin(cfgPath, name string, log *slog.Logger) error {
	_, router, err := loadEnvs(cfgPath, log)
	if err != nil {
		return err
	}
	e, ok := router.Env(name)
	if !ok {
		return fmt.Errorf("no environment %s", name)
	}
	c, ok := e.Tokens().(*connect.Connector)
	if !ok {
		return fmt.Errorf("environment %s reads its token from a file; there is nothing to log in to", name)
	}
	ctx := context.Background()
	if err := c.Login(ctx); err != nil {
		return err
	}
	return printAccess(ctx, router, []string{name})
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

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/RapidataAI/pgauth/internal/api"
)

// Env is one pgauth deployment the connector reaches: its Postgres port, its HTTPS API and where
// its tokens come from.
type Env struct {
	Name string
	up   *upstream
	// API is the base URL of serve's HTTPS endpoints.
	API  string
	HTTP *http.Client
	// CacheFile keeps the last discovery that succeeded, so bare names survive an API outage.
	CacheFile string
	// LookupTimeout bounds a discovery request; default lookupTimeout.
	LookupTimeout time.Duration

	mu     sync.Mutex
	disc   *api.Discovery
	discAt time.Time
}

// discoveryTTL bounds how stale the instance list used to resolve "<env>/<db>" may be while the
// API answers; when it does not, the last answer is used however old.
const discoveryTTL = time.Minute

// lookupTimeout keeps a client from hanging on an unreachable API before it sees the error.
const lookupTimeout = 3 * time.Second

// unreachableError says the API could not be asked and how to connect without it.
type unreachableError struct {
	api, cause string
}

func (e unreachableError) Error() string {
	return "pgauth api " + e.api + " unreachable (" + e.cause + ")"
}

func shortCause(err error) string {
	msg := err.Error()
	for _, c := range []struct{ match, cause string }{
		{"deadline exceeded", "timeout"},
		{"Client.Timeout", "timeout"},
		{"connection refused", "connection refused"},
		{"no such host", "no such host"},
		{"certificate", "TLS certificate not trusted"},
		{"network is unreachable", "network unreachable"},
	} {
		if strings.Contains(msg, c.match) {
			return c.cause
		}
	}
	if i := strings.LastIndex(msg, ": "); i >= 0 && i+2 < len(msg) {
		msg = msg[i+2:]
	}
	return msg
}

func (e *Env) Tokens() TokenSource { return e.up.tokens }

// Discovery fetches serve's /.well-known/pgauth, cached for discoveryTTL in memory and, as the
// last known answer, in CacheFile. When the API cannot be reached, the last answer is used.
func (e *Env) Discovery(ctx context.Context) (*api.Discovery, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disc != nil && time.Since(e.discAt) < discoveryTTL {
		return e.disc, nil
	}
	timeout := e.LookupTimeout
	if timeout == 0 {
		timeout = lookupTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d api.Discovery
	err := getJSON(lookupCtx, e.HTTP, e.API+"/.well-known/pgauth", "", &d)
	if err == nil {
		e.disc, e.discAt = &d, time.Now()
		e.saveCache(&d)
		return e.disc, nil
	}
	if e.disc == nil {
		e.disc = e.loadCache()
	}
	if e.disc != nil {
		return e.disc, nil
	}
	return nil, unreachableError{api: e.API, cause: shortCause(err)}
}

type cachedDiscovery struct {
	API       string        `json:"api"`
	Discovery api.Discovery `json:"discovery"`
}

func (e *Env) saveCache(d *api.Discovery) {
	if e.CacheFile == "" {
		return
	}
	b, err := json.Marshal(cachedDiscovery{API: e.API, Discovery: *d})
	if err != nil || os.MkdirAll(filepath.Dir(e.CacheFile), 0o700) != nil {
		return
	}
	tmp := e.CacheFile + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, e.CacheFile)
	}
}

// loadCache returns the cached discovery if it was written for this environment's API.
func (e *Env) loadCache() *api.Discovery {
	if e.CacheFile == "" {
		return nil
	}
	b, err := os.ReadFile(e.CacheFile)
	if err != nil {
		return nil
	}
	var c cachedDiscovery
	if json.Unmarshal(b, &c) != nil || c.API != e.API {
		return nil
	}
	return &c.Discovery
}

// Access lists what this environment's token reaches.
func (e *Env) Access(ctx context.Context) ([]api.Access, error) {
	tok, err := e.up.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	var out []api.Access
	return out, getJSON(ctx, e.HTTP, e.API+"/v1/access", tok, &out)
}

// Address is the shortest name that reaches instance/db: "<env>/<db>" when no other instance has
// a database of that name, else "<env>/<instance>/<db>".
func (e *Env) Address(d *api.Discovery, instance, db string) string {
	if len(candidates(d, db)) == 1 {
		return e.Name + "/" + db
	}
	return e.Name + "/" + instance + "/" + db
}

func candidates(d *api.Discovery, db string) []string {
	var out []string
	for _, in := range d.Instances {
		if slices.Contains(in.Databases, db) {
			out = append(out, in.Name)
		}
	}
	return out
}

// Router sends each connection to the environment its database name starts with.
type Router struct {
	envs map[string]*Env
	log  *slog.Logger
}

func NewRouter(envs []*Env, log *slog.Logger) *Router {
	r := &Router{envs: map[string]*Env{}, log: log}
	for _, e := range envs {
		r.envs[e.Name] = e
	}
	return r
}

func (r *Router) Env(name string) (*Env, bool) {
	e, ok := r.envs[name]
	return e, ok
}

func (r *Router) Names() []string {
	names := make([]string, 0, len(r.envs))
	for n := range r.envs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Resolve maps "<env>/<db>" or "<env>/<instance>/<db>" to the environment and the "<instance>/<db>"
// pgauth serve expects; "<db>" alone is looked up in the environment's instances.
func (r *Router) Resolve(ctx context.Context, database string) (*Env, string, error) {
	parts := strings.Split(database, "/")
	e, ok := r.envs[parts[0]]
	if len(parts) < 2 || len(parts) > 3 || !ok {
		return nil, "", routeError{fmt.Sprintf("use <env>/<db>; environments: %s", strings.Join(r.Names(), ", "))}
	}
	return r.resolveIn(ctx, e, parts[1:], database)
}

// ResolveOn resolves a name on a listener bound to one environment: "<db>" and "<instance>/<db>"
// are inside it, and an "<env>/..." name is accepted only for that same environment.
func (r *Router) ResolveOn(ctx context.Context, env, database string) (*Env, string, error) {
	e := r.envs[env]
	parts := strings.Split(database, "/")
	if other, ok := r.envs[parts[0]]; ok && len(parts) > 1 {
		if other != e {
			return nil, "", routeError{fmt.Sprintf("this port serves %s; %s names %s, use its port or the main one", env, database, parts[0])}
		}
		parts = parts[1:]
	}
	if len(parts) > 2 || parts[0] == "" {
		return nil, "", routeError{fmt.Sprintf("this port serves %s; use <db> or <instance>/<db>", env)}
	}
	return r.resolveIn(ctx, e, parts, database)
}

// resolveIn handles the part after the environment: "<instance>/<db>" or "<db>".
func (r *Router) resolveIn(ctx context.Context, e *Env, parts []string, database string) (*Env, string, error) {
	if len(parts) == 2 {
		return e, parts[0] + "/" + parts[1], nil
	}
	db := parts[0]
	d, err := e.Discovery(ctx)
	if err != nil {
		var unreachable unreachableError
		if errors.As(err, &unreachable) {
			return nil, "", routeError{fmt.Sprintf("%v; use %s/<instance>/%s to connect without it", err, e.Name, db)}
		}
		return nil, "", routeError{fmt.Sprintf("cannot look up %s: %v", database, err)}
	}
	switch c := candidates(d, db); len(c) {
	case 1:
		return e, c[0] + "/" + db, nil
	case 0:
		return nil, "", routeError{fmt.Sprintf("%s serves no database %s; `pgauth ls %s` lists what you can reach", e.Name, db, e.Name)}
	default:
		addrs := make([]string, len(c))
		for i, in := range c {
			addrs[i] = e.Name + "/" + in + "/" + db
		}
		return nil, "", routeError{fmt.Sprintf("%s is on several instances; use %s", database, strings.Join(addrs, " or "))}
	}
}

// Serve accepts local connections on ln until ctx ends; with env set, names resolve inside it.
func (r *Router) Serve(ctx context.Context, ln net.Listener, env string) error {
	f := &forwarder{log: r.log, route: func(ctx context.Context, database string) (target, error) {
		resolve := r.Resolve
		if env != "" {
			resolve = func(ctx context.Context, database string) (*Env, string, error) {
				return r.ResolveOn(ctx, env, database)
			}
		}
		e, db, err := resolve(ctx, database)
		if err != nil {
			return target{}, err
		}
		return target{up: e.up, database: db, label: database}, nil
	}}
	return f.serve(ctx, ln)
}

func getJSON(ctx context.Context, client *http.Client, url, bearer string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("%s: %s", url, e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// FetchDiscovery reads serve's /.well-known/pgauth at apiURL.
func FetchDiscovery(ctx context.Context, client *http.Client, apiURL string) (*api.Discovery, error) {
	var d api.Discovery
	if err := getJSON(ctx, client, strings.TrimSuffix(apiURL, "/")+"/.well-known/pgauth", "", &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// PrintAccess writes what each named environment's token reaches to out, and per-environment
// failures to errOut; an environment with nothing reachable gets the server's access help.
func (r *Router) PrintAccess(ctx context.Context, out, errOut io.Writer, names []string) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DATABASE\tLEVEL")
	failed := false
	var empty []string
	for _, name := range names {
		e := r.envs[name]
		d, err := e.Discovery(ctx)
		var access []api.Access
		if err == nil {
			access, err = e.Access(ctx)
		}
		if err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", name, err)
			failed = true
			continue
		}
		for _, a := range access {
			fmt.Fprintf(w, "%s\t%s\n", e.Address(d, a.Instance, a.Database), a.Level)
		}
		if len(access) == 0 {
			msg := name + ": no database is reachable with this token."
			if d.AccessHelp != "" {
				msg += " " + strings.Join(strings.Fields(d.AccessHelp), " ")
			}
			empty = append(empty, msg)
		}
	}
	_ = w.Flush()
	for _, msg := range empty {
		fmt.Fprintln(out, msg)
	}
	if failed {
		return errors.New("some environments could not be listed")
	}
	return nil
}

// Package api serves pgauth's HTTPS endpoints: public discovery for connectors, and the access a
// token has, so a client can list what it may reach without trying every database.
package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/RapidataAI/pgauth/internal/config"
	"github.com/RapidataAI/pgauth/internal/rbac"
	"github.com/RapidataAI/pgauth/internal/token"
)

// Discovery is the body of GET /.well-known/pgauth.
type Discovery struct {
	Postgres    string     `json:"postgres"`
	Issuer      string     `json:"issuer"`
	Audience    string     `json:"audience"`
	CLIClientID string     `json:"cli_client_id"`
	Scopes      Scopes     `json:"scopes"`
	Instances   []Instance `json:"instances"`
}

type Scopes struct {
	Read  string `json:"read"`
	Write string `json:"write"`
}

type Instance struct {
	Name      string   `json:"name"`
	Databases []string `json:"databases"`
}

// Access is one entry of GET /v1/access: a database the token reaches and its level after the scope cap.
type Access struct {
	Instance string `json:"instance"`
	Database string `json:"database"`
	Level    string `json:"level"`
}

type Server struct {
	cfg      *config.Config
	verifier *token.Verifier
	rbac     *rbac.Store
}

func New(cfg *config.Config, verifier *token.Verifier, store *rbac.Store) *Server {
	return &Server{cfg: cfg, verifier: verifier, rbac: store}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/pgauth", s.discovery)
	mux.HandleFunc("GET /v1/access", s.access)
	return mux
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	d := Discovery{
		Postgres:    s.cfg.Discovery.Postgres,
		Issuer:      s.cfg.OIDC.Issuer,
		Audience:    s.cfg.OIDC.Audience,
		CLIClientID: s.cfg.Discovery.CLIClientID,
		Scopes:      Scopes{Read: s.cfg.OIDC.Scopes.Read, Write: s.cfg.OIDC.Scopes.Write},
	}
	if d.Postgres == "" {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		_, port, _ := net.SplitHostPort(s.cfg.Listen)
		d.Postgres = net.JoinHostPort(host, port)
	}
	for _, in := range s.cfg.Instances {
		d.Instances = append(d.Instances, Instance{Name: in.Name, Databases: in.Databases})
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) access(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "send the database token as Authorization: Bearer <token>")
		return
	}
	claims, err := s.verifier.Verify(r.Context(), raw)
	if err != nil {
		code := http.StatusUnauthorized
		if !errors.Is(err, token.ErrDenied) {
			code = http.StatusInternalServerError
		}
		writeError(w, code, err.Error())
		return
	}
	policy := s.rbac.Policy()
	if policy == nil {
		writeError(w, http.StatusServiceUnavailable, "access rules are not loaded")
		return
	}
	scopeCap := rbac.ScopeCap(claims.Scopes, s.cfg.OIDC.Scopes.Read, s.cfg.OIDC.Scopes.Write)
	who := rbac.Who{User: claims.Username, Groups: claims.Groups, FoldUser: s.cfg.OIDC.FoldUsername()}
	out := []Access{}
	for _, in := range s.cfg.Instances {
		for _, db := range in.Databases {
			granted, _ := policy.Access(who, in.Name, db)
			if level := min(granted, scopeCap); level > rbac.None {
				out = append(out, Access{Instance: in.Name, Database: db, Level: level.String()})
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// Package token verifies database tokens against an OIDC issuer and reads the claims pgauth acts on.
package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/RapidataAI/pgauth/internal/config"
)

type Claims struct {
	Subject  string
	ClientID string
	// Roles are the raw entries of the roles claim, e.g. "main/order:reader".
	Roles []string
}

type Verifier struct {
	cfg      config.OIDC
	verifier atomic.Pointer[oidc.IDTokenVerifier]
}

func NewVerifier(cfg config.OIDC) *Verifier { return &Verifier{cfg: cfg} }

// Start runs OIDC discovery and a first JWKS fetch, retrying until both succeed or ctx ends.
func (v *Verifier) Start(ctx context.Context, log *slog.Logger) {
	for wait := time.Second; ; wait = min(2*wait, 30*time.Second) {
		err := v.discover(ctx)
		if err == nil {
			return
		}
		log.Warn("oidc issuer not ready", "issuer", v.cfg.Issuer, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (v *Verifier) discover(ctx context.Context) error {
	provider, err := oidc.NewProvider(ctx, v.cfg.Issuer)
	if err != nil {
		return err
	}
	var meta struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", meta.JWKSURL, resp.Status)
	}
	v.verifier.Store(provider.Verifier(&oidc.Config{ClientID: v.cfg.Audience}))
	return nil
}

// Ready reports whether discovery and the first JWKS fetch succeeded.
func (v *Verifier) Ready() bool { return v.verifier.Load() != nil }

// ErrDenied wraps every reason a token is refused; its message is safe to show the client.
var ErrDenied = errors.New("token rejected")

func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	verifier := v.verifier.Load()
	if verifier == nil {
		return Claims{}, fmt.Errorf("%w: issuer not reachable yet", ErrDenied)
	}
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %s", ErrDenied, reason(err))
	}
	var all map[string]any
	if err := tok.Claims(&all); err != nil {
		return Claims{}, fmt.Errorf("%w: unreadable claims", ErrDenied)
	}
	c := Claims{Subject: tok.Subject}
	if c.Subject == "" {
		return Claims{}, fmt.Errorf("%w: no sub claim", ErrDenied)
	}
	c.ClientID, _ = all[v.cfg.ClientIDClaim].(string)
	if c.ClientID == "" {
		c.ClientID, _ = all["azp"].(string)
	}
	if len(v.cfg.AllowedClients) > 0 && !slices.Contains(v.cfg.AllowedClients, c.ClientID) {
		return Claims{}, fmt.Errorf("%w: client %q is not allowed", ErrDenied, c.ClientID)
	}
	c.Roles, err = stringList(all[v.cfg.RolesClaim])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: claim %s: %v", ErrDenied, v.cfg.RolesClaim, err)
	}
	return c, nil
}

func reason(err error) string {
	var expired *oidc.TokenExpiredError
	switch {
	case errors.As(err, &expired):
		return "token expired"
	case strings.Contains(err.Error(), "audience"):
		return "wrong audience"
	case strings.Contains(err.Error(), "different provider"):
		return "wrong issuer"
	case strings.Contains(err.Error(), "signature"):
		return "bad signature"
	default:
		return "invalid token"
	}
}

func stringList(v any) ([]string, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case string:
		return strings.Fields(v), nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, errors.New("entries must be strings")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, errors.New("must be an array or a space-separated string")
	}
}

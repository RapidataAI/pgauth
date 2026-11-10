package connect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func discover(ctx context.Context, issuer string) (*discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: %s", resp.Status)
	}
	var d discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, errors.New("oidc discovery: missing authorization or token endpoint")
	}
	return &d, nil
}

// login runs the authorization code flow with PKCE through the browser and a loopback redirect.
func (c *Connector) login(ctx context.Context, d *discovery) (*tokenResponse, error) {
	verifier := randomString(32)
	challenge := sha256.Sum256([]byte(verifier))
	state := randomString(16)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		var res result
		switch {
		case q.Get("state") != state:
			res.err = errors.New("login: state mismatch")
		case q.Get("error") != "":
			res.err = fmt.Errorf("login: %s: %s", q.Get("error"), q.Get("error_description"))
		default:
			res.code = q.Get("code")
		}
		if res.err != nil {
			http.Error(w, res.err.Error(), http.StatusBadRequest)
		} else {
			fmt.Fprintln(w, "pgauth: logged in. You can close this tab.")
		}
		select {
		case got <- res:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.opts.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {c.opts.Scope},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	if c.opts.Resource != "" {
		params.Set("resource", c.opts.Resource)
	}
	authURL := d.AuthorizationEndpoint + "?" + params.Encode()
	c.log.Info("log in through your browser", "url", authURL)
	if err := c.opts.OpenBrowser(authURL); err != nil {
		c.log.Warn("could not open a browser; open the URL yourself", "error", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var res result
	select {
	case res = <-got:
	case <-ctx.Done():
		return nil, errors.New("login: timed out waiting for the browser")
	}
	if res.err != nil {
		return nil, res.err
	}
	return c.tokenRequest(ctx, d, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	})
}

func (c *Connector) refresh(ctx context.Context, d *discovery, refreshToken string) (*tokenResponse, error) {
	return c.tokenRequest(ctx, d, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

func (c *Connector) tokenRequest(ctx context.Context, d *discovery, form url.Values) (*tokenResponse, error) {
	form.Set("client_id", c.opts.ClientID)
	if c.opts.Resource != "" {
		form.Set("resource", c.opts.Resource)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var t tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, fmt.Errorf("token endpoint: %s", resp.Status)
	}
	if t.Error != "" {
		return nil, fmt.Errorf("token endpoint: %s: %s", t.Error, t.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK || t.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint: %s without an access token", resp.Status)
	}
	return &t, nil
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

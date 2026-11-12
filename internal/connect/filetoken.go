package connect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

// FileSource reads the token from a file on every connection, so a refreshed file is picked up
// without a restart. Problems fail only the connection that hit them.
type FileSource struct {
	Path string
	// Field names the JSON field holding the token; empty means the file is the raw JWT.
	Field string
	// StatusFile, when it exists, explains a missing or stale token better than the path can.
	StatusFile string
	now        func() time.Time
}

// freshFor is how long a token must still be valid to be handed out.
const freshFor = 10 * time.Second

func (f *FileSource) Token(context.Context) (string, error) {
	tok, err := f.read()
	if err != nil {
		return "", f.explain()
	}
	exp, err := expiry(tok)
	if err != nil {
		return "", f.explain()
	}
	now := time.Now
	if f.now != nil {
		now = f.now
	}
	if !exp.IsZero() && exp.Before(now().Add(freshFor)) {
		return "", f.explain()
	}
	return tok, nil
}

func (f *FileSource) read() (string, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return "", err
	}
	if f.Field == "" {
		return strings.TrimSpace(string(b)), nil
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", err
	}
	tok, _ := doc[f.Field].(string)
	if tok == "" {
		return "", errors.New("no " + f.Field)
	}
	return tok, nil
}

func (f *FileSource) explain() error {
	if f.StatusFile != "" {
		if b, err := os.ReadFile(f.StatusFile); err == nil && strings.TrimSpace(string(b)) != "" {
			return errors.New(strings.TrimSpace(string(b)))
		}
	}
	return errors.New("token file " + f.Path + " missing or expired")
}

// expiry reads a JWT's exp without verifying it; pgauth serve verifies.
func expiry(jwt string) (time.Time, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return time.Time{}, errors.New("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, err
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, err
	}
	if claims.Exp == 0 {
		return time.Time{}, nil
	}
	return time.Unix(int64(claims.Exp), 0), nil
}

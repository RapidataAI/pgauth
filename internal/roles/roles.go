// Package roles creates, reuses and drops temporary roles on one Postgres instance.
package roles

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"crypto/pbkdf2"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Spec describes the temporary role one holder needs for one set of rights.
type Spec struct {
	Subject  string
	Username string
	ClientID string
	// Roles are the claim entries that granted access; they decide the name.
	Roles  []string
	Groups []string
}

// Name is prefix + 8 characters of the subject + 6 hex characters of a hash over subject, client and roles.
func (s Spec) Name(prefix string) string {
	var short strings.Builder
	for _, r := range strings.ToLower(s.Subject) {
		if short.Len() == 8 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			short.WriteRune(r)
		}
	}
	return prefix + short.String() + "_" + s.key()[:6]
}

func (s Spec) key() string {
	roles := slices.Clone(s.Roles)
	slices.Sort(roles)
	h := sha256.Sum256([]byte(s.Subject + "\x00" + s.ClientID + "\x00" + strings.Join(roles, ",")))
	return hex.EncodeToString(h[:])
}

type comment struct {
	Subject  string    `json:"sub"`
	Username string    `json:"user,omitempty"`
	ClientID string    `json:"client"`
	Created  time.Time `json:"created"`
}

// Manager owns the temporary roles of one instance. Several managers on several pods may share
// an instance: every create, reuse and drop runs under a Postgres advisory lock on the role name.
type Manager struct {
	pool      *pgxpool.Pool
	tempGroup string
	prefix    string
	secret    []byte
	log       *slog.Logger

	mu    sync.Mutex
	roles map[string]*entry
}

type entry struct {
	mu     sync.Mutex
	refs   int // guarded by Manager.mu
	key    string
	exists bool
}

// NewManager uses pool, logged in as the issuer, to manage roles; secret derives the role passwords,
// so every pod sharing the issuer credential derives the same password for a role.
func NewManager(pool *pgxpool.Pool, tempGroup, prefix string, secret []byte, log *slog.Logger) *Manager {
	return &Manager{pool: pool, tempGroup: tempGroup, prefix: prefix, secret: secret, log: log, roles: map[string]*entry{}}
}

// Acquire makes sure the role for spec exists and calls login with its name and password. Every
// successful Acquire must be paired with one Release once that login's connection has closed.
func (m *Manager) Acquire(ctx context.Context, spec Spec, login func(role, password string) (pid uint32, err error)) (role string, pid uint32, err error) {
	role = spec.Name(m.prefix)
	m.mu.Lock()
	e := m.roles[role]
	if e == nil {
		e = &entry{key: spec.key()}
		m.roles[role] = e
	}
	e.refs++
	m.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.key != spec.key() {
		m.releaseLocked(ctx, role, e, 0)
		return role, 0, fmt.Errorf("role name %s collides with another holder", role)
	}
	password := m.password(role)
	if e.exists {
		pid, err = login(role, password)
	} else {
		err = m.withLock(ctx, role, func(conn *pgxpool.Conn) error {
			if err := m.ensure(ctx, conn, role, spec); err != nil {
				return err
			}
			e.exists = true
			pid, err = login(role, password)
			return err
		})
	}
	if err != nil {
		m.releaseLocked(ctx, role, e, 0)
		return role, 0, err
	}
	return role, pid, nil
}

// Release drops role once the last connection using it, whose backend was pid, has closed here
// and no other session (another pgauth pod's) still uses it.
func (m *Manager) Release(ctx context.Context, role string, pid uint32) {
	m.mu.Lock()
	e := m.roles[role]
	m.mu.Unlock()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	m.releaseLocked(ctx, role, e, pid)
}

func (m *Manager) releaseLocked(ctx context.Context, role string, e *entry, pid uint32) {
	m.mu.Lock()
	e.refs--
	last := e.refs == 0
	m.mu.Unlock()
	if last && e.exists {
		if err := m.drop(ctx, role, pid); err != nil {
			m.log.Error("drop temporary role", "role", role, "error", err)
		}
		e.exists = false
	}
	m.mu.Lock()
	if e.refs == 0 && !e.exists {
		delete(m.roles, role)
	}
	m.mu.Unlock()
}

func (m *Manager) ensure(ctx context.Context, conn *pgxpool.Conn, role string, spec Spec) error {
	verifier, err := scramVerifier(m.password(role))
	if err != nil {
		return err
	}
	ident := pgx.Identifier{role}.Sanitize()
	var isTemp, exists bool
	err = conn.QueryRow(ctx, `
		SELECT true, pg_has_role(r.oid, $2::name, 'MEMBER')
		FROM pg_roles r WHERE r.rolname = $1`, role, m.tempGroup).Scan(&exists, &isTemp)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if exists {
		if !isTemp {
			return fmt.Errorf("role %s exists and is not a member of %s", role, m.tempGroup)
		}
		_, err = conn.Exec(ctx, "ALTER ROLE "+ident+" PASSWORD "+literal(verifier))
		return err
	}
	groups := []string{m.tempGroup}
	groups = append(groups, spec.Groups...)
	quoted := make([]string, len(groups))
	for i, g := range groups {
		quoted[i] = pgx.Identifier{g}.Sanitize()
	}
	c, err := json.Marshal(comment{Subject: spec.Subject, Username: spec.Username, ClientID: spec.ClientID, Created: time.Now().UTC()})
	if err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "CREATE ROLE "+ident+" LOGIN INHERIT PASSWORD "+literal(verifier)+" IN ROLE "+strings.Join(quoted, ", ")); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "COMMENT ON ROLE "+ident+" IS "+literal(string(c))); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// drop waits for pid, the backend of the connection just closed, to exit, then drops role unless
// another session still uses it.
func (m *Manager) drop(ctx context.Context, role string, pid uint32) error {
	return m.withLock(ctx, role, func(conn *pgxpool.Conn) error {
		if pid != 0 {
			if err := waitForExit(ctx, conn, pid); err != nil {
				return err
			}
		}
		var sessions int
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename = $1", role).Scan(&sessions); err != nil {
			return err
		}
		if sessions > 0 {
			m.log.Info("temporary role still in use elsewhere, not dropped", "role", role, "sessions", sessions)
			return nil
		}
		_, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize())
		return err
	})
}

func waitForExit(ctx context.Context, conn *pgxpool.Conn, pid uint32) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		var alive bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)", int32(pid)).Scan(&alive); err != nil {
			return err
		}
		if !alive {
			return nil
		}
		if time.Now().After(deadline) {
			_, err := conn.Exec(ctx, "SELECT pg_terminate_backend($1, 1000)", int32(pid))
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Sweep drops temporary roles left by a pgauth that crashed: members of the temp group with no
// session that were created more than minAge ago, so a role another pod is just logging in with stays.
func (m *Manager) Sweep(ctx context.Context, minAge time.Duration) (dropped int, err error) {
	rows, err := m.pool.Query(ctx, `
		SELECT r.rolname, coalesce(shobj_description(r.oid, 'pg_authid'), '')
		FROM pg_roles r
		JOIN pg_auth_members am ON am.member = r.oid
		JOIN pg_roles g ON g.oid = am.roleid
		WHERE g.rolname = $1 AND NOT am.admin_option AND r.rolname <> current_user AND starts_with(r.rolname, $2)`,
		m.tempGroup, m.prefix)
	if err != nil {
		return 0, err
	}
	type candidate struct{ Role, Comment string }
	cands, err := pgx.CollectRows(rows, pgx.RowToStructByPos[candidate])
	if err != nil {
		return 0, err
	}
	for _, c := range cands {
		var meta comment
		if json.Unmarshal([]byte(c.Comment), &meta) == nil && time.Since(meta.Created) < minAge {
			continue
		}
		m.mu.Lock()
		_, local := m.roles[c.Role]
		m.mu.Unlock()
		if local {
			continue
		}
		if err := m.drop(ctx, c.Role, 0); err != nil {
			m.log.Error("sweep temporary role", "role", c.Role, "error", err)
			continue
		}
		dropped++
	}
	return dropped, nil
}

func (m *Manager) withLock(ctx context.Context, role string, fn func(*pgxpool.Conn) error) error {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(hashtext($1))", role); err != nil {
		return err
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(hashtext($1))", role); err != nil {
			conn.Conn().Close(ctx)
		}
	}()
	return fn(conn)
}

func (m *Manager) password(role string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte("pgauth temporary role\x00" + role))
	return hex.EncodeToString(mac.Sum(nil))
}

// scramVerifier hashes password the way Postgres stores it, so the plain password never reaches the server's logs.
func scramVerifier(password string) (string, error) {
	const iterations = 4096
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	clientKey := hmacSum(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSum(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func hmacSum(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

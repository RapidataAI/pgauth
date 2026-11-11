package rbac

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ReadDir returns every *.yaml file directly in dir, sorted by name, except kustomization.yaml so
// the rules can live next to the kustomization that builds their ConfigMap.
func ReadDir(dir string) ([]File, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	files := make([]File, 0, len(paths))
	for _, p := range paths {
		if filepath.Base(p) == "kustomization.yaml" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		files = append(files, File{Name: p, Data: b})
	}
	return files, nil
}

// Load parses and compiles files in one step.
func Load(files []File, instances Instances) (*Policy, error) {
	res, errs := Parse(files)
	if len(errs) > 0 {
		return nil, errs
	}
	p, errs := Compile(res, instances)
	if len(errs) > 0 {
		return nil, errs
	}
	return p, nil
}

// Store holds the live policy. A rejected set never replaces a valid one.
type Store struct {
	instances Instances
	log       *slog.Logger
	// OnLoad is called after every load attempt that saw changed input.
	OnLoad func(err error)

	policy atomic.Pointer[Policy]
	mu     sync.Mutex
	digest [32]byte
	status Status
}

type Status struct {
	Loaded     bool
	LoadedAt   time.Time
	RejectedAt time.Time
	Rejected   error // the last rejection, cleared by the next valid load
}

func NewStore(instances Instances, log *slog.Logger) *Store {
	return &Store{instances: instances, log: log}
}

func (s *Store) Policy() *Policy { return s.policy.Load() }

func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Update compiles files and makes them live if they are valid and differ from the last input.
func (s *Store) Update(files []File) error {
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.Name + "\x00"))
		h.Write(f.Data)
		h.Write([]byte{0})
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Loaded || s.status.Rejected != nil {
		if digest == s.digest {
			return s.status.Rejected
		}
	}
	s.digest = digest
	p, err := Load(files, s.instances)
	if err != nil {
		s.status.Rejected, s.status.RejectedAt = err, time.Now()
		s.log.Error("access rules rejected; keeping the last valid set", "loaded", s.status.Loaded, "error", err)
	} else {
		s.policy.Store(p)
		roles, bindings := p.Size()
		s.status = Status{Loaded: true, LoadedAt: time.Now()}
		s.log.Info("access rules loaded", "roles", roles, "bindings", bindings)
	}
	if s.OnLoad != nil {
		s.OnLoad(err)
	}
	return err
}

// WatchDir loads dir now and again every interval until ctx ends.
func (s *Store) WatchDir(ctx context.Context, dir string, interval time.Duration) {
	for {
		files, err := ReadDir(dir)
		if err == nil {
			_ = s.Update(files)
		} else {
			err = errors.Join(errors.New("read "+dir), err)
			s.mu.Lock()
			s.status.Rejected, s.status.RejectedAt = err, time.Now()
			s.digest = [32]byte{}
			s.mu.Unlock()
			s.log.Error("access rules unreadable; keeping the last valid set", "error", err)
			if s.OnLoad != nil {
				s.OnLoad(err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

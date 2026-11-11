// Package share keeps in-memory, single-use, encrypted file shares.
package share

import (
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("share not found")
	ErrConsumed = errors.New("share already downloaded")
	ErrExpired  = errors.New("share expired")
	ErrFull     = errors.New("too many files held in memory; delete old shares first")
)

type Share struct {
	Token     string
	Key       []byte
	Header    Header
	Cipher    []byte
	CreatedAt time.Time
	ExpiresAt time.Time

	// plain is retained only so the owner can re-issue the share with a
	// fresh token and key after it was consumed. Never served.
	plain []byte

	Downloaded   bool
	DownloadedAt time.Time
	RemoteAddr   string
}

// Summary is what the local admin UI sees. It never includes the key.
type Summary struct {
	Token        string    `json:"token"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Size         int64     `json:"size"`
	CipherSize   int       `json:"cipherSize"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Expired      bool      `json:"expired"`
	Downloaded   bool      `json:"downloaded"`
	DownloadedAt time.Time `json:"downloadedAt,omitempty"`
	RemoteAddr   string    `json:"remoteAddr,omitempty"`
}

type Store struct {
	// MaxShares and MaxBytes cap what a long-running instance keeps in RAM
	// (plaintext and ciphertext both count). Zero means unlimited.
	MaxShares int
	MaxBytes  int64

	mu     sync.Mutex
	shares map[string]*Share
}

func NewStore() *Store {
	return &Store{shares: make(map[string]*Share)}
}

func (sh *Share) memSize() int64 { return int64(len(sh.plain) + len(sh.Cipher)) }

// fits reports whether a share of about extra bytes can be added. Callers
// hold s.mu.
func (s *Store) fits(extra int64) bool {
	if s.MaxShares > 0 && len(s.shares) >= s.MaxShares {
		return false
	}
	if s.MaxBytes > 0 {
		total := extra
		for _, sh := range s.shares {
			total += sh.memSize()
		}
		if total > s.MaxBytes {
			return false
		}
	}
	return true
}

func (s *Store) Create(h Header, data []byte, ttl time.Duration) (*Share, error) {
	s.mu.Lock()
	ok := s.fits(2*int64(len(data)) + 1024)
	s.mu.Unlock()
	if !ok {
		return nil, ErrFull
	}
	return s.create(h, data, ttl)
}

func (s *Store) create(h Header, data []byte, ttl time.Duration) (*Share, error) {
	key := randomBytes(KeySize)
	h.Size = int64(len(data))
	ct, err := Seal(key, h, data)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sh := &Share{
		Token:     base64.RawURLEncoding.EncodeToString(randomBytes(16)),
		Key:       key,
		Header:    h,
		Cipher:    ct,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		plain:     data,
	}
	s.mu.Lock()
	s.shares[sh.Token] = sh
	s.mu.Unlock()
	return sh, nil
}

// Renew replaces a share with a brand-new token and key for the same file.
func (s *Store) Renew(token string, ttl time.Duration) (*Share, error) {
	s.mu.Lock()
	old, ok := s.shares[token]
	if ok {
		delete(s.shares, token)
	}
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return s.create(old.Header, old.plain, ttl)
}

func (s *Store) Delete(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.shares[token]; !ok {
		return false
	}
	delete(s.shares, token)
	return true
}

// Status reports whether a token can still be downloaded, without consuming it.
func (s *Store) Status(token string) (*Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(token)
}

// Consume atomically marks the share as downloaded and returns it. A second
// call with the same token fails with ErrConsumed.
func (s *Store) Consume(token, remote string) (*Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, err := s.check(token)
	if err != nil {
		return nil, err
	}
	sh.Downloaded = true
	sh.DownloadedAt = time.Now()
	sh.RemoteAddr = remote
	return sh, nil
}

func (s *Store) check(token string) (*Share, error) {
	sh, ok := s.shares[token]
	if !ok {
		return nil, ErrNotFound
	}
	if sh.Downloaded {
		return nil, ErrConsumed
	}
	if time.Now().After(sh.ExpiresAt) {
		return nil, ErrExpired
	}
	return sh, nil
}

func (s *Store) List() []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Summary, 0, len(s.shares))
	now := time.Now()
	for _, sh := range s.shares {
		out = append(out, Summary{
			Token:        sh.Token,
			Name:         sh.Header.Name,
			Type:         sh.Header.Type,
			Size:         sh.Header.Size,
			CipherSize:   len(sh.Cipher),
			CreatedAt:    sh.CreatedAt,
			ExpiresAt:    sh.ExpiresAt,
			Expired:      now.After(sh.ExpiresAt),
			Downloaded:   sh.Downloaded,
			DownloadedAt: sh.DownloadedAt,
			RemoteAddr:   sh.RemoteAddr,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// HasActive reports whether any link can still be downloaded, i.e. whether
// the tunnel has to stay up.
func (s *Store) HasActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, sh := range s.shares {
		if !sh.Downloaded && now.Before(sh.ExpiresAt) {
			return true
		}
	}
	return false
}

// Sweep drops shares that are expired or were downloaded more than grace ago.
func (s *Store) Sweep(grace time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for t, sh := range s.shares {
		if sh.Downloaded && now.Sub(sh.DownloadedAt) > grace {
			delete(s.shares, t)
		} else if !sh.Downloaded && now.Sub(sh.ExpiresAt) > grace {
			delete(s.shares, t)
		}
	}
}

// KeyParam is the URL-fragment form of the key.
func (sh *Share) KeyParam() string {
	return base64.RawURLEncoding.EncodeToString(sh.Key)
}

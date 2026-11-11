package share

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSealLayout(t *testing.T) {
	key := make([]byte, KeySize)
	out, err := Seal(key, Header{Name: "a.txt", Type: "text/plain", Size: 3}, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, out[:NonceSize], out[NonceSize:], nil)
	if err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(plain[:4])
	var h Header
	if err := json.Unmarshal(plain[4:4+n], &h); err != nil {
		t.Fatal(err)
	}
	if h.Name != "a.txt" {
		t.Fatalf("name = %q", h.Name)
	}
	if string(plain[4+n:]) != "abc" {
		t.Fatalf("data = %q", plain[4+n:])
	}
	if _, err := Seal(make([]byte, 31), h, nil); err == nil {
		t.Fatal("31-byte key accepted")
	}
}

func TestConsumeOnce(t *testing.T) {
	s := NewStore()
	sh, err := s.Create(Header{Name: "a"}, []byte("x"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(sh.Token, "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(sh.Token, "1.2.3.4"); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume: %v", err)
	}
	if _, err := s.Status(sh.Token); !errors.Is(err, ErrConsumed) {
		t.Fatalf("status: %v", err)
	}
}

func TestExpired(t *testing.T) {
	s := NewStore()
	sh, _ := s.Create(Header{Name: "a"}, []byte("x"), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := s.Status(sh.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("status: %v", err)
	}
	if s.HasActive() {
		t.Fatal("expired share counts as active")
	}
}

func TestCreateFull(t *testing.T) {
	s := NewStore()
	s.MaxShares = 1
	if _, err := s.Create(Header{}, []byte("x"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(Header{}, []byte("x"), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("got %v", err)
	}
	s2 := NewStore()
	s2.MaxBytes = 10
	if _, err := s2.Create(Header{}, []byte("sixsix"), time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("got %v", err)
	}
}

func TestRenewNewTokenAndKey(t *testing.T) {
	s := NewStore()
	old, _ := s.Create(Header{Name: "a"}, []byte("x"), time.Minute)
	nw, err := s.Renew(old.Token, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if nw.Token == old.Token || string(nw.Key) == string(old.Key) {
		t.Fatal("token or key reused")
	}
	if _, err := s.Status(old.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old token: %v", err)
	}
}

func TestListHasNoKey(t *testing.T) {
	s := NewStore()
	sh, _ := s.Create(Header{Name: "a"}, []byte("x"), time.Minute)
	b, _ := json.Marshal(s.List())
	if strings.Contains(string(b), sh.KeyParam()) {
		t.Fatal("list leaks the key")
	}
}

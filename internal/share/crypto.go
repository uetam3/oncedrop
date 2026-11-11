package share

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Header describes the file and travels inside the encrypted payload, so the
// tunnel provider never sees the file name or MIME type.
type Header struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

const (
	KeySize   = 32
	NonceSize = 12
)

// Seal produces: nonce(12) || AES-256-GCM( u32be(len(header)) || header JSON || data ).
// The browser decrypts it with WebCrypto (AES-GCM, 128-bit tag appended, which
// is Go's default layout).
func Seal(key []byte, h Header, data []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes", KeySize)
	}
	hdr, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 4+len(hdr)+len(data))
	binary.BigEndian.PutUint32(plain[:4], uint32(len(hdr)))
	copy(plain[4:], hdr)
	copy(plain[4+len(hdr):], data)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, NonceSize+len(plain)+gcm.Overhead())
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, nil), nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return b
}

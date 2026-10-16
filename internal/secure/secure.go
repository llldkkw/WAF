// Package secure holds small cryptographic helpers: at-rest encryption of
// secrets (notification tokens, TOTP seeds) and random token generation.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Box encrypts and decrypts small secrets with AES-256-GCM.
type Box struct {
	aead cipher.AEAD
	key  []byte
}

// LoadOrCreateKey reads the 32-byte master key from path, creating it with
// mode 0600 on first start. Back this file up: without it, stored secrets
// cannot be decrypted.
func LoadOrCreateKey(path string) (*Box, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key %s must be 32 bytes, got %d", path, len(key))
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("master key %s is readable by group/others (mode %o); run chmod 600", path, st.Mode().Perm())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead, key: key}, nil
}

func (b *Box) Seal(plain []byte) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func (b *Box) Open(enc string) ([]byte, error) {
	if enc == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return b.aead.Open(nil, raw[:ns], raw[ns:], nil)
}

// MAC derives a keyed hash, used for signing one-off links.
func (b *Box) MAC(purpose string, msg []byte) []byte {
	m := hmac.New(sha256.New, b.key)
	m.Write([]byte(purpose))
	m.Write([]byte{0})
	m.Write(msg)
	return m.Sum(nil)
}

// Token returns n random bytes hex-encoded.
func Token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// HashToken is used to store session tokens: the DB never sees the raw value.
func HashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

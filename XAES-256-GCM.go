// Package xaes256gcm implements the [XAES-256-GCM] extended-nonce AEAD, an
// efficient combination of a NIST SP 800-108r1 KDF and AES-256-GCM.
//
// [XAES-256-GCM]: https://c2sp.org/XAES-256-GCM
package xaes256gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// KeySize is the size of XAES-256-GCM keys.
const KeySize = 32

// NonceSize is the size of nonces that must be passed to Seal and Open,
// if the AEAD was created with [NewWithManualNonces].
const NonceSize = 24

// OverheadWithManualNonces is the difference between the lengths of a plaintext
// and its ciphertext, if the AEAD was created with [NewWithManualNonces].
const OverheadWithManualNonces = 16

// Overhead is the difference between the lengths of a plaintext and its
// ciphertext, if the AEAD was created with [New]. It includes the length of the
// randomly-generated and automatically-managed nonce.
const Overhead = 40

type xaes256gcm struct {
	c  cipher.Block
	k1 [aes.BlockSize]byte
}

// NewWithManualNonces returns a new XAES-256-GCM instance that expects 24-byte
// nonces to be passed to Open and Seal. nonces can be safely generated with
// [crypto/rand.Read]. key must be exactly 32 bytes long.
//
// Most applications should use [New] instead, which automatically generates
// random nonces and prepends them to the ciphertext. (Note that New is not
// implemented yet.)
func NewWithManualNonces(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("xaes256gcm: bad key length")
	}

	x := new(xaes256gcm)

	x.c, _ = aes.NewCipher(key)
	x.c.Encrypt(x.k1[:], x.k1[:])

	// Shift left k1 by one bit, then XOR with 0b10000111 if the MSB was set.
	var msb byte
	for i := len(x.k1) - 1; i >= 0; i-- {
		msb, x.k1[i] = x.k1[i]>>7, x.k1[i]<<1|msb
	}
	x.k1[len(x.k1)-1] ^= msb * 0b10000111

	return x, nil
}

func (*xaes256gcm) NonceSize() int {
	return NonceSize
}

func (*xaes256gcm) Overhead() int {
	return OverheadWithManualNonces
}

func (x *xaes256gcm) deriveKey(nonce []byte) []byte {
	k := make([]byte, 0, 2*aes.BlockSize)
	k = append(k, 0, 1, 'X', 0)
	k = append(k, nonce...)
	k = append(k, 0, 2, 'X', 0)
	k = append(k, nonce...)
	subtle.XORBytes(k[:aes.BlockSize], k[:aes.BlockSize], x.k1[:])
	subtle.XORBytes(k[aes.BlockSize:], k[aes.BlockSize:], x.k1[:])
	x.c.Encrypt(k[:aes.BlockSize], k[:aes.BlockSize])
	x.c.Encrypt(k[aes.BlockSize:], k[aes.BlockSize:])
	return k
}

func (x *xaes256gcm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("xaes256gcm: bad nonce length")
	}

	k, n := x.deriveKey(nonce[:12]), nonce[12:]
	c, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(c)
	return a.Seal(dst, n, plaintext, additionalData)
}

var errOpen = errors.New("xaes256gcm: message authentication failed")

func (x *xaes256gcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("xaes256gcm: bad nonce length")
	}

	k, n := x.deriveKey(nonce[:12]), nonce[12:]
	c, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(c)
	return a.Open(dst, n, ciphertext, additionalData)
}

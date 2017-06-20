package cmd

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"runtime"

	"github.com/aead/poly"
	"golang.org/x/crypto/blake2b"
)

const (
	// Sha256 specifies SHA-256 for bitrot protection
	Sha256 BitRotHashAlgorithm = "sha256"
	// Blake2b specifies BLAKE2b for bitrot protection
	Blake2b BitRotHashAlgorithm = "blake2b"
	// Poly1305 specifies Poly1305 for bitrot protection
	Poly1305 BitRotHashAlgorithm = "poly1305"
	// Ghash specifies GHASH for bitrot protection
	Ghash BitRotHashAlgorithm = "ghash"
)

// DefaultBitRotHashAlgorithm is the default BitRotHashAlgorithm for the
// specific platform: On arm64: SHA-256 - otherwise Poly1305
var DefaultBitRotHashAlgorithm BitRotHashAlgorithm

func init() {
	switch runtime.GOARCH {
	case "arm64":
		// As a special case for ARM64 we use an optimized
		// version of SHA256.
		DefaultBitRotHashAlgorithm = Sha256
	default:
		// Default for all other architectures is poly1305.
		DefaultBitRotHashAlgorithm = Blake2b
	}
}

// BitRotHashAlgorithm is a hash algorithm which can be used to
// detect bitrot.
type BitRotHashAlgorithm string

// KeySize returns the size of the key for the specific algorithm in bytes.
// If the algorithm does not require a key it returns 0.
func (a BitRotHashAlgorithm) KeySize() int {
	switch a {
	case Sha256, Blake2b:
		return 0
	case Poly1305, Ghash:
		return 32
	default:
		panic(fmt.Sprintf("erasure: unknown algorithm %s", a))
	}
}

// RequireKey returns true if the algorithm requires a key.
// In this case the key must be KeySize() bytes long.
func (a BitRotHashAlgorithm) RequireKey() bool {
	switch a {
	case Sha256, Blake2b:
		return false
	case Poly1305, Ghash:
		return true
	default:
		panic(fmt.Sprintf("erasure: unknown algorithm %s", a))
	}
}

// IsValid returns true iff the algorithm is a valid bitrot protection mechanism
func (a BitRotHashAlgorithm) IsValid() bool {
	return a == Sha256 || a == Blake2b || a == Poly1305 || a == Ghash
}

// BitRotHash defines a hash function which can be used to dected bitrot.
type BitRotHash interface {
	io.Writer

	Sum(b []byte) []byte

	Verify(expected []byte) bool

	Key() (key []byte, ok bool)
}

// NewBitRotHash returns new a BitRotHash which implements the given algorithm
// and uses the provided key. If the algorithm does not require a key the key can
// be arbitrary - nil is also valid.
func NewBitRotHash(alg BitRotHashAlgorithm, key []byte) BitRotHash {
	switch alg {
	case Sha256:
		return erasureHasher{sha256.New()}
	case Blake2b:
		b2, _ := blake2b.New512(nil)
		return erasureHasher{b2}
	case Poly1305:
		if len(key) != 32 {
			panic("invalid key size")
		}
		var k [32]byte
		copy(k[:], key)
		return &erasureAuthenticator{poly.NewPoly1305(k), k[:]}
	case Ghash:
		panic("GHASH is not implemented yet")
	default:
		panic(fmt.Sprintf("erasure: unknown algorithm %s", alg))
	}
}

type erasureHasher struct {
	hash.Hash
}

func (e erasureHasher) Key() (key []byte, ok bool) { return }

func (e erasureHasher) Verify(expected []byte) bool {
	checksum := e.Sum(nil)
	return subtle.ConstantTimeCompare(checksum, expected) == 1
}

type erasureAuthenticator struct {
	poly.Hash
	key []byte
}

func (e *erasureAuthenticator) Key() (key []byte, ok bool) { return e.key, true }

func (e *erasureAuthenticator) Verify(expected []byte) bool {
	checksum := e.Sum(nil)
	return subtle.ConstantTimeCompare(checksum, expected) == 1
}

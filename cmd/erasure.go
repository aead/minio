package cmd

import (
	"crypto/subtle"

	"github.com/minio/minio/pkg/bitrot"
)

// NewBitrotInfo creates a non-verified BitrotInfo with the given algorithm, key and checksum.
func NewBitrotInfo(algorithm bitrot.Algorithm, key, sum []byte) *BitrotInfo {
	return &BitrotInfo{
		Algorithm: algorithm,
		Key:       key,
		Sum:       sum,
	}
}

// BitrotInfo holds the general information for bitrot protection/verification
type BitrotInfo struct {
	Algorithm bitrot.Algorithm
	Key       []byte
	Sum       []byte

	verified bool
}

// IsCipher returns true if the bitrot algorithm is a cipher
func (b *BitrotInfo) IsCipher() bool {
	return b.Algorithm == bitrot.AESGCM || b.Algorithm == bitrot.ChaCha20Poly1305
}

// MustVerify returns true if a bitrot verification is necessary.
func (b *BitrotInfo) MustVerify() bool { return !b.verified }

// Verify compares the given sum with the expected checksum.
// It returns true iff sum and the expected checksum are equal.
// Verify marks the bitrot info as verified - so MustVerify() will return false.
func (b *BitrotInfo) Verify(sum []byte) bool {
	b.verified = true
	return subtle.ConstantTimeCompare(b.Sum, sum) == 1
}

// ErasureFileInfo holds general information for erasure file operations
type ErasureFileInfo struct {
	Disks     []StorageAPI
	Size      int64
	Algorithm bitrot.Algorithm
	Keys      [][]byte
	Checksums [][]byte
}

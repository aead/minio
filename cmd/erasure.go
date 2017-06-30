package cmd

import (
	"github.com/minio/minio/pkg/bitrot"
)

// BitrotInfo holds the general information for bitrot protection/verification
type BitrotInfo struct {
	Algorithm bitrot.Algorithm
	Key       []byte
	Sum       []byte
}

// IsCipher returns true if the bitrot algorithm is a cipher
func (b *BitrotInfo) IsCipher() bool {
	return b.Algorithm == bitrot.AESGCM || b.Algorithm == bitrot.ChaCha20Poly1305
}

// MustVerify returns true if a verification is necessary.
func (b *BitrotInfo) MustVerify() bool {
	return len(b.Sum) != 0
}

// ErasureFileInfo holds general information for erasure file operations
type ErasureFileInfo struct {
	Disks     []StorageAPI
	Size      int64
	Keys      [][]byte
	Checksums [][]byte
}

/*
 * Minio Cloud Storage, (C) 2017, 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package chacha20poly1305 implements the ChaCha20Poly1305 AEAD construction
// used by the minio server for encryption and bitrot protection.
package chacha20poly1305

import (
	"encoding/binary"
	"fmt"

	"github.com/aead/chacha20/chacha"
	"github.com/aead/poly1305"
	"github.com/minio/minio/pkg/bitrot"
)

// New returns a new Hash. It encrypts and authenticates all data
// which is passed to it. The given keyNonce must be 44 byte long and
// unique. New assumes that the nonce is within the first 12 bytes of keyNonce
// and the secret key within the last 32 bytes.
func New(keyNonce []byte, mode bitrot.Mode) bitrot.Hash {
	if len(keyNonce) != 12+32 {
		panic(fmt.Sprintf("bad key length: #%d", len(keyNonce)))
	}

	key, nonce := make([]byte, 32), make([]byte, 12)
	copy(nonce, keyNonce[:12])
	copy(key, keyNonce[12:])

	cipher, _ := chacha.NewCipher(nonce, key, 20)

	var polyKey [32]byte
	cipher.XORKeyStream(polyKey[:], polyKey[:])
	cipher.SetCounter(1)

	hash := poly1305.New(polyKey)
	if mode == bitrot.Protect {
		return &encryptedWriter{aeadCipher{cipher, hash, 0}}
	}
	return &decryptedWriter{aeadCipher{cipher, hash, 0}}
}

type encryptedWriter struct {
	aeadCipher
}

func (w *encryptedWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.encrypt(p)
	return
}

type decryptedWriter struct {
	aeadCipher
}

func (w *decryptedWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.decrypt(p)
	return
}

type aeadCipher struct {
	cipher  *chacha.Cipher
	hash    *poly1305.Hash
	byteCtr uint64
}

func (c *aeadCipher) encrypt(p []byte) {
	c.cipher.XORKeyStream(p, p)
	c.hash.Write(p)
	c.byteCtr += uint64(len(p))
}

func (c *aeadCipher) decrypt(p []byte) {
	c.hash.Write(p)
	c.cipher.XORKeyStream(p, p)
	c.byteCtr += uint64(len(p))
}

func (c *aeadCipher) Sum(b []byte) []byte {
	h0 := *(c.hash)

	var pad [poly1305.TagSize]byte
	if padCt := c.byteCtr % poly1305.TagSize; padCt > 0 {
		h0.Write(pad[:poly1305.TagSize-padCt])
	}
	binary.LittleEndian.PutUint64(pad[8:], c.byteCtr)
	h0.Write(pad[:])

	return h0.Sum(b)
}

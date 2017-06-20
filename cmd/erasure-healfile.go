/*
 * Minio Cloud Storage, (C) 2016 Minio, Inc.
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

package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

// Heals the erasure coded file. reedsolomon.Reconstruct() is used to reconstruct the missing parts.
func erasureHealFile(latestDisks []StorageAPI, outDatedDisks []StorageAPI, volume, path, healBucket, healPath string,
	size, blockSize int64, dataBlocks, parityBlocks int, alg BitRotHashAlgorithm) (checkSums, keys []string, err error) {

	var offset int64
	remainingSize := size

	// Hash for bitrot protection.
	key := make([]byte, alg.KeySize())
	hasher := make([]BitRotHash, len(outDatedDisks))
	for i := range hasher {
		if alg.RequireKey() {
			_, err = io.ReadFull(rand.Reader, key)
			if err != nil {
				return
			}
		}
		hasher[i] = NewBitRotHash(alg, key)
	}
	for remainingSize > 0 {
		curBlockSize := blockSize
		if remainingSize < curBlockSize {
			curBlockSize = remainingSize
		}

		// Calculate the block size that needs to be read from each disk.
		curEncBlockSize := getChunkSize(curBlockSize, dataBlocks)

		// Memory for reading data from disks and reconstructing missing data using erasure coding.
		enBlocks := make([][]byte, len(latestDisks))

		// Read data from the latest disks.
		// FIXME: no need to read from all the disks. dataBlocks+1 is enough.
		for index, disk := range latestDisks {
			if disk == nil {
				continue
			}
			enBlocks[index] = make([]byte, curEncBlockSize)
			_, err := disk.ReadFile(volume, path, offset, enBlocks[index])
			if err != nil {
				enBlocks[index] = nil
			}
		}

		// Reconstruct missing data.
		err := decodeData(enBlocks, dataBlocks, parityBlocks)
		if err != nil {
			return nil, nil, err
		}

		// Write to the healPath file.
		for i, disk := range outDatedDisks {
			if disk == nil {
				continue
			}
			err := disk.AppendFile(healBucket, healPath, enBlocks[i])
			if err != nil {
				return nil, nil, traceError(err)
			}
			hasher[i].Write(enBlocks[i])
		}
		remainingSize -= curBlockSize
		offset += curEncBlockSize
	}

	// Checksums for the bit rot.
	checkSums = make([]string, len(outDatedDisks))
	keys = make([]string, len(outDatedDisks))
	for i, disk := range outDatedDisks {
		if disk == nil {
			continue
		}
		checkSums[i] = hex.EncodeToString(hasher[i].Sum(nil))
		if key, ok := hasher[i].Key(); ok {
			keys[i] = hex.EncodeToString(key)
		}
	}
	return checkSums, keys, nil
}

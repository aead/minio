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

	"github.com/minio/minio/pkg/bitrot"
)

// Heals the erasure coded file. reedsolomon.Reconstruct() is used to reconstruct the missing parts.
func erasureHealFile(latestDisks []StorageAPI, outDatedDisks []StorageAPI, volume, path, healBucket, healPath string,
	size, blockSize int64, dataBlocks, parityBlocks int, algo bitrot.Algorithm) (f ErasureFileInfo, err error) {

	var offset int64
	remainingSize := size

	// Hash for bitrot protection.
	binKeys, hashWriters, err := newBitrotProtection(len(outDatedDisks), algo, rand.Reader)
	if err != nil {
		return
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
			_, err = disk.ReadFile(volume, path, offset, enBlocks[index])
			if err != nil {
				enBlocks[index] = nil
			}
		}

		// Reconstruct missing data.
		err = decodeData(enBlocks, dataBlocks, parityBlocks)
		if err != nil {
			return
		}

		// Write to the healPath file.
		for index, disk := range outDatedDisks {
			if disk == nil {
				continue
			}
			err := disk.AppendFile(healBucket, healPath, enBlocks[index])
			if err != nil {
				return f, traceError(err)
			}
			hashWriters[index].Write(enBlocks[index])
		}
		remainingSize -= curBlockSize
		offset += curEncBlockSize
	}

	f = ErasureFileInfo{
		Disks:     outDatedDisks,
		Size:      size,
		Keys:      make([][]byte, len(outDatedDisks)),
		Checksums: make([][]byte, len(outDatedDisks)),
	}
	for i, disk := range outDatedDisks {
		if disk == nil {
			continue
		}
		f.Keys[i] = binKeys[i]
		f.Checksums[i] = hashWriters[i].Sum(nil)
	}
	return f, nil
}

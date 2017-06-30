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
	"io"
	"sync"

	"github.com/klauspost/reedsolomon"
	"github.com/minio/minio/pkg/bitrot"
)

// erasureCreateFile - writes an entire stream by erasure coding to
// all the disks, writes also calculate individual block's checksum
// for future bit-rot protection.
func erasureCreateFile(disks []StorageAPI, volume, path string, reader io.Reader, allowEmpty bool, blockSize int64,
	dataBlocks, parityBlocks int, algo bitrot.Algorithm, writeQuorum int) (f ErasureFileInfo, err error) {

	// Allocated blockSized buffer for reading from incoming stream.
	buf := make([]byte, blockSize)

	binKeys, hashWriters, err := newBitrotProtection(len(disks), algo, rand.Reader)
	if err != nil {
		return
	}

	// Read until io.EOF, erasure codes data and writes to all disks.
	var newDisks []StorageAPI
	var bytesWritten int64
	for {
		var blocks [][]byte
		n, rErr := io.ReadFull(reader, buf)
		// FIXME: this is a bug in Golang, n == 0 and err ==
		// io.ErrUnexpectedEOF for io.ReadFull function.
		if n == 0 && rErr == io.ErrUnexpectedEOF {
			return f, traceError(rErr)
		}
		if rErr == io.EOF {
			// We have reached EOF on the first byte read, io.Reader
			// must be 0bytes, we don't need to erasure code
			// data. Will create a 0byte file instead.
			if bytesWritten == 0 && allowEmpty {
				blocks = make([][]byte, len(disks))
				newDisks, err = appendFile(disks, volume, path, blocks, hashWriters, writeQuorum)
				if err != nil {
					return
				}
			} // else we have reached EOF after few reads, no need to
			// add an additional 0bytes at the end.
			break
		}
		if rErr != nil && rErr != io.ErrUnexpectedEOF {
			return f, traceError(rErr)
		}
		if n > 0 {
			// Returns encoded blocks.
			var enErr error
			blocks, enErr = encodeData(buf[0:n], dataBlocks, parityBlocks)
			if enErr != nil {
				return f, enErr
			}

			// Write to all disks.
			if newDisks, err = appendFile(disks, volume, path, blocks, hashWriters, writeQuorum); err != nil {
				return
			}
			bytesWritten += int64(n)
		}
	}

	f = ErasureFileInfo{
		Disks:     newDisks,
		Size:      bytesWritten,
		Algorithm: algo,
		Keys:      binKeys,
		Checksums: make([][]byte, len(disks)),
	}
	for i := range f.Checksums {
		f.Checksums[i] = hashWriters[i].Sum(nil)
	}
	return f, nil
}

// encodeData - encodes incoming data buffer into
// dataBlocks+parityBlocks returns a 2 dimensional byte array.
func encodeData(dataBuffer []byte, dataBlocks, parityBlocks int) ([][]byte, error) {
	rs, err := reedsolomon.New(dataBlocks, parityBlocks)
	if err != nil {
		return nil, traceError(err)
	}
	// Split the input buffer into data and parity blocks.
	var blocks [][]byte
	blocks, err = rs.Split(dataBuffer)
	if err != nil {
		return nil, traceError(err)
	}

	// Encode parity blocks using data blocks.
	err = rs.Encode(blocks)
	if err != nil {
		return nil, traceError(err)
	}

	// Return encoded blocks.
	return blocks, nil
}

// appendFile - append data buffer at path.
func appendFile(disks []StorageAPI, volume, path string, enBlocks [][]byte, hashWriters []bitrot.Hash, writeQuorum int) ([]StorageAPI, error) {
	var wg = &sync.WaitGroup{}
	var wErrs = make([]error, len(disks))
	// Write encoded data to quorum disks in parallel.
	for index, disk := range disks {
		if disk == nil {
			wErrs[index] = traceError(errDiskNotFound)
			continue
		}
		wg.Add(1)
		// Write encoded data in routine.
		go func(index int, disk StorageAPI) {
			defer wg.Done()
			// Calculate hash for each blocks.
			hashWriters[index].Write(enBlocks[index])
			wErr := disk.AppendFile(volume, path, enBlocks[index])
			if wErr != nil {
				wErrs[index] = traceError(wErr)
				return
			}

			// Successfully wrote.
			wErrs[index] = nil
		}(index, disk)
	}

	// Wait for all the appends to finish.
	wg.Wait()

	return evalDisks(disks, wErrs), reduceWriteQuorumErrs(wErrs, objectOpIgnoredErrs, writeQuorum)
}

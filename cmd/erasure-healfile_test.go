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
	"bytes"
	"crypto/rand"
	"os"
	"path"
	"testing"
	"time"

	"encoding/binary"

	humanize "github.com/dustin/go-humanize"
)

type seededRand struct {
	val [8]byte
}

func (s seededRand) Read(p []byte) (n int, err error) {
	n = len(p)
	for len(p) > 0 {
		nn := 8
		if len(p) < 8 {
			nn = len(p)
		}
		copy(p, s.val[:nn])
		p = p[nn:]
	}
	return
}

// Test erasureHealFile()
func TestErasureHealFile(t *testing.T) {
	// make rand.Reader a seeded entropy source
	cryptoReader := rand.Reader
	var val [8]byte
	binary.LittleEndian.PutUint64(val[:], uint64(time.Now().Unix()))
	rand.Reader = seededRand{}
	defer func() { rand.Reader = cryptoReader }()

	// Initialize environment needed for the test.
	dataBlocks := 7
	parityBlocks := 7
	blockSize := int64(blockSizeV1)
	setup, err := newErasureTestSetup(dataBlocks, parityBlocks, blockSize)
	if err != nil {
		t.Error(err)
		return
	}
	defer setup.Remove()

	disks := setup.disks

	// Prepare a slice of 1MiB with random data.
	data := make([]byte, 1*humanize.MiByte)
	_, err = rand.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	// Create a test file.
	result, err := erasureCreateFile(disks, "testbucket", "testobject1", bytes.NewReader(data), true, blockSize, dataBlocks, parityBlocks, DefaultBitRotHashAlgorithm, dataBlocks+1)
	if err != nil {
		t.Fatal(err)
	}
	if result.size != int64(len(data)) {
		t.Errorf("erasureCreateFile returned %d, expected %d", result.size, len(data))
	}

	latest := make([]StorageAPI, len(disks))   // Slice of latest disks
	outDated := make([]StorageAPI, len(disks)) // Slice of outdated disks

	// Test case when one part needs to be healed.
	dataPath := path.Join(setup.diskPaths[0], "testbucket", "testobject1")
	err = os.Remove(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	copy(latest, disks)
	latest[0] = nil
	outDated[0] = disks[0]

	healCheckSums, _, err := erasureHealFile(latest, outDated, "testbucket", "testobject1", "testbucket", "testobject1", 1*humanize.MiByte, blockSize, dataBlocks, parityBlocks, DefaultBitRotHashAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	// Checksum of the healed file should match.
	if result.hashes[0] != healCheckSums[0] {
		t.Errorf("Healing failed, data does not match - Seed: %v\n", rand.Reader)
	}

	// Test case when parityBlocks number of disks need to be healed.
	// Should succeed.
	copy(latest, disks)
	for index := 0; index < parityBlocks; index++ {
		dataPath := path.Join(setup.diskPaths[index], "testbucket", "testobject1")
		err = os.Remove(dataPath)
		if err != nil {
			t.Fatal(err)
		}

		latest[index] = nil
		outDated[index] = disks[index]
	}

	healCheckSums, _, err = erasureHealFile(latest, outDated, "testbucket", "testobject1", "testbucket", "testobject1", 1*humanize.MiByte, blockSize, dataBlocks, parityBlocks, DefaultBitRotHashAlgorithm)
	if err != nil {
		t.Fatal(err)
	}

	// Checksums of the healed files should match.
	for index := 0; index < parityBlocks; index++ {
		if result.hashes[index] != healCheckSums[index] {
			t.Errorf("Healing failed, data does not match - Seed: %v\n", rand.Reader)
		}
	}
	for index := dataBlocks; index < len(disks); index++ {
		if healCheckSums[index] != "" {
			t.Errorf("expected healCheckSums[%d] to be empty", index)
		}
	}

	// Test case when parityBlocks+1 number of disks need to be healed.
	// Should fail.
	copy(latest, disks)
	for index := 0; index < parityBlocks+1; index++ {
		dataPath := path.Join(setup.diskPaths[index], "testbucket", "testobject1")
		err = os.Remove(dataPath)
		if err != nil {
			t.Fatal(err)
		}

		latest[index] = nil
		outDated[index] = disks[index]
	}
	_, _, err = erasureHealFile(latest, outDated, "testbucket", "testobject1", "testbucket", "testobject1", 1*humanize.MiByte, blockSize, dataBlocks, parityBlocks, DefaultBitRotHashAlgorithm)
	if err == nil {
		t.Error("Expected erasureHealFile() to fail when the number of available disks <= parityBlocks")
	}
}

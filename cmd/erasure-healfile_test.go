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

	humanize "github.com/dustin/go-humanize"
)

// Test erasureHealFile()
func TestErasureHealFile(t *testing.T) {
	orig := rand.Reader
	rand.Reader = NewDerministicRandom()
	defer func() { rand.Reader = orig }()
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
	file, err := erasureCreateFile(disks, "testbucket", "testobject1", bytes.NewReader(data), true, blockSize, dataBlocks, parityBlocks, defaultBitRotAlgorithm, dataBlocks+1)
	if err != nil {
		t.Fatal(err)
	}
	if file.Size != int64(len(data)) {
		t.Errorf("erasureCreateFile returned %d, expected %d", file.Size, len(data))
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

	healFile, err := erasureHealFile(latest, outDated, "testbucket", "testobject1", "testbucket", "testobject1", 1*humanize.MiByte, blockSize, dataBlocks, parityBlocks, defaultBitRotAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	// Checksum of the healed file should match.
	if file.Checksums[0] != healFile.Checksums[0] {
		t.Error("Healing failed, data does not match.")
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

	healFile, err = erasureHealFile(latest, outDated, "testbucket", "testobject1", "testbucket", "testobject1", 1*humanize.MiByte, blockSize, dataBlocks, parityBlocks, defaultBitRotAlgorithm)
	if err != nil {
		t.Fatal(err)
	}

	// Checksums of the healed files should match.
	for index := 0; index < parityBlocks; index++ {
		if file.Checksums[index] != healFile.Checksums[index] {
			t.Error("Healing failed, data does not match.")
		}
	}
	for index := dataBlocks; index < len(disks); index++ {
		if healFile.Checksums[index] != "" {
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
	_, err = erasureHealFile(latest, outDated, "testbucket", "testobject1", "testbucket", "testobject1", 1*humanize.MiByte, blockSize, dataBlocks, parityBlocks, defaultBitRotAlgorithm)
	if err == nil {
		t.Error("Expected erasureHealFile() to fail when the number of available disks <= parityBlocks")
	}
}

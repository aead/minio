// MinIO Cloud Storage, (C) 2021 MinIO, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !fips

package madmin

import (
	"github.com/minio/minio/pkg/argon2"
	"github.com/secure-io/sio-go/sioutil"
)

var idKey func([]byte, []byte, []byte, []byte, uint32) []byte

func init() {
	idKey = argon2.NewIDKey(1, 64*1024, 4)
}

// useAES returns true if the executing CPU provides
// AES-GCM hardware instructions and an optimized
// assembler implementation is available.
func useAES() bool { return sioutil.NativeAES() }

// generateHash generates bcrypt password hash
func generateHash(password []byte, salt []byte) []byte {
	return idKey(password, salt, nil, nil, 32)
}

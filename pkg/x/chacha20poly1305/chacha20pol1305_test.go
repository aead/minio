package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/minio/minio/pkg/bitrot"
)

func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var newTestCases = []struct {
	key       []byte
	plaintext []byte
	sum       []byte
}{
	{
		key:       mustDecode("000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000"),
		plaintext: nil,
		sum:       mustDecode("4eb972c9a8fb3a1b382bb4d36f5ffad1"),
	},
	{
		key:       mustDecode("000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000"),
		plaintext: mustDecode("00"),
		sum:       mustDecode("bedcfd1809ff3c10adf8277fcc0581b8"),
	},
	{
		key:       mustDecode("000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000001"),
		plaintext: mustDecode("00"),
		sum:       mustDecode("2dbf7ae9248db8b96563943e27bc5569"),
	},
	{
		key:       mustDecode("000000000000000000000001" + "0000000000000000000000000000000000000000000000000000000000000000"),
		plaintext: mustDecode("00"),
		sum:       mustDecode("fcdb7ac5fcb63c63cf2e15bd4899be5d"),
	},
	{
		key:       mustDecode("00000000000000000000ffff" + "1000000000000000000000000000000000000000000000000000000000000002"),
		plaintext: mustDecode("000000000000000000000000000000000000000000000000000000000000000001"),
		sum:       mustDecode("277f7c563e714adfbfc73dc72f60165a"),
	},
	{
		key:       mustDecode("000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000000"),
		plaintext: mustDecode("0000000000000000000000000000000000000000000000000000000000000000"),
		sum:       mustDecode("95f82bfae8f522217f8b7db39b40ad06"),
	},
}

func TestNew(t *testing.T) {
	for i, test := range newTestCases {
		data := make([]byte, len(test.plaintext))
		copy(data, test.plaintext)

		cipher := New(test.key, bitrot.Protect)
		cipher.Write(data)
		sum := cipher.Sum(nil)
		if !bytes.Equal(test.sum, sum) {
			t.Errorf("Test %d: checksum mismatch in protection mode: got %v , want: %v", i, hex.EncodeToString(sum), hex.EncodeToString(test.sum))
		}

		cipher = New(test.key, bitrot.Verify)
		cipher.Write(data)
		sum = cipher.Sum(nil)
		if !bytes.Equal(test.sum, sum) {
			t.Errorf("Test %d: checksum mismatch in verification mode: got %v , want: %v", i, hex.EncodeToString(sum), hex.EncodeToString(test.sum))
		}
		if !bytes.Equal(test.plaintext, data) {
			t.Errorf("Test %d: failed to decrypt data: got %v , want: %v", i, hex.EncodeToString(data), hex.EncodeToString(test.plaintext))
		}
	}

	// Test that New fails for a bad key
	defer func() {
		if err := recover(); err == nil {
			t.Fatal("New should panic if the key is not 44 bytes long, but it passes")
		}
	}()
	_ = New(make([]byte, 32), bitrot.Protect)
}

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
		key:       mustDecode("0000000000000000000000000000000000000000000000000000000000000000"),
		plaintext: nil,
		sum:       mustDecode("13d8de523538ee1187dc7a44d346c303"),
	},
	{
		key:       mustDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		plaintext: mustDecode("00"),
		sum:       mustDecode("cc0244fc1d59bbcb801e6ac2e09191ef"),
	},
	{
		key:       mustDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		plaintext: mustDecode("000000000000000000000000000000000000000000000000000000000000000000"),
		sum:       mustDecode("517f9c9b841a411c5957b6118c1fff13"),
	},
	{
		key:       mustDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		plaintext: mustDecode("100000000000000000000000000000000000000000000000000000000000000000"),
		sum:       mustDecode("c3ca8d71f610698f8cfed3bcb56e2f0f"),
	},
	{
		key:       mustDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
		plaintext: mustDecode("00000000000000000000000000000000000000000000000000000000000001"),
		sum:       mustDecode("a034618b1af0c1e63ffbe924161344ef"),
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
			t.Fatal("New should panic if the key is not 32 bytes long, but it passes")
		}
	}()
	_ = New(make([]byte, 31), bitrot.Protect)
}

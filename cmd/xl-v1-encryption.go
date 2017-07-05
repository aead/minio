package cmd

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"github.com/minio/minio/pkg/bitrot"
	sha256 "github.com/minio/sha256-simd"
)

const (
	ssePrefix         = "X-Amz-Server-Side-Encryption-Customer-"
	sseAlgorithm      = ssePrefix + "Algorithm"
	sseCustomerKey    = ssePrefix + "Key"
	sseCustomerKeyMD5 = ssePrefix + "Key-Md5"

	sseSecretKeyMAC  = ssePrefix + "Key-Hash"
	sseSecretKeySalt = ssePrefix + "Key-Salt"
)

// ServerSideEncryptionInfo contains the algorithm and the client provided
// secret key for server-side-encryption (SSE-C)
type ServerSideEncryptionInfo struct {
	Algorithm bitrot.Algorithm
	SecretKey []byte
}

// WriteToMetadata generates a random salt and the HMAC of the secret key and stores both values
// in the provided metadata map. This is necessary to verify the client provided encryption key.
func (e *ServerSideEncryptionInfo) WriteToMetadata(metadata map[string]string, random io.Reader) error {
	// TODO(aead): Think about it - there are actually better constructions (like HKDF or even pwd-based KDF)?!
	salt := make([]byte, 32)
	if _, err := io.ReadFull(random, salt); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, e.SecretKey)
	if _, err := mac.Write(salt); err != nil {
		return err
	}
	metadata[sseSecretKeyMAC] = hex.EncodeToString(mac.Sum(nil))
	metadata[sseSecretKeySalt] = hex.EncodeToString(salt)
	return nil
}

// VerifyHMAC reads the salt the HMAC of the secret encryption key from the metadata, computes the
// HMAC of the client provided key and compares both HMAC values. It returns an error if both
// HMAC values don't match.
func (e *ServerSideEncryptionInfo) VerifyHMAC(metadata map[string]string) error {
	hash, err := hex.DecodeString(metadata[sseSecretKeyMAC])
	if err != nil {
		return traceError(err)
	}
	salt, err := hex.DecodeString(metadata[sseSecretKeySalt])
	if err != nil {
		return traceError(err)
	}
	mac := hmac.New(sha256.New, e.SecretKey)
	if _, err = mac.Write(salt); err != nil {
		return traceError(err)
	}
	sum := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sum, hash) == 1 {
		err = errors.New("secret key checksum mismatch")
	}
	return nil
}

func isServerSideEncryptonRequest(metadata map[string]string) bool {
	_, ok := metadata[sseAlgorithm]
	return ok
}

func isEncryptedObject(metadata map[string]string) bool {
	_, okSalt := metadata[sseSecretKeySalt]
	_, okMAC := metadata[sseSecretKeyMAC]
	return okMAC && okSalt
}

// ParseServerSideEncryptionInfo takes the client-provided headers and extracts the ServerSideEncryptionInfo.
// It returns an error if the client provided metadata does not contain a valid encryption request.
func ParseServerSideEncryptionInfo(metadata map[string]string) (info *ServerSideEncryptionInfo, err error) {
	if metadata[sseAlgorithm] != "AES256" { // this is currently hardcoded by AWS - whatever you mean with "AES256", Amazon. ¯\_(ツ)_/¯
		return info, Errorf("missing %s", sseAlgorithm)
	}
	bas64Key := metadata[sseCustomerKey]
	if bas64Key == "" {
		return info, Errorf("missing %s", sseCustomerKey)
	}
	bas64KeyMD5 := metadata[sseCustomerKeyMD5]
	if bas64Key == "" {
		return info, Errorf("missing %s", sseCustomerKeyMD5)
	}
	delete(metadata, sseAlgorithm)
	delete(metadata, sseCustomerKey)
	delete(metadata, sseCustomerKeyMD5)

	algorithm := bitrot.ChaCha20Poly1305
	if bitrot.AESGCM.Available() {
		algorithm = bitrot.AESGCM
	}
	secretKey, err := base64.StdEncoding.DecodeString(bas64Key)
	if err != nil {
		return info, err
	}
	keyMD5, err := base64.StdEncoding.DecodeString(bas64KeyMD5)
	if err != nil {
		return info, err
	}
	if len(secretKey) != 32 { // SSE-Keys must be 256 bit
		return info, errors.New("server-side-encryption key is not 256 long")
	}
	if sum := md5.Sum(secretKey); subtle.ConstantTimeCompare(sum[:], keyMD5) != 1 {
		return info, errors.New("server-side-encryption key does not match MD5 checksum")
	}
	return &ServerSideEncryptionInfo{Algorithm: algorithm, SecretKey: secretKey}, nil
}

func parseServerSideEncryptionCopyHeaders(metadata map[string]string) (alg bitrot.Algorithm, key []byte, err error) {
	algorithm := metadata["x-amz-copy-source​-server-side​-encryption​-customer-algorithm"]
	if algorithm != "AES256" { // this is currently hardcoded by AWS - whatever you mean with "AES256", Amazon. ¯\_(ツ)_/¯
		return bitrot.UnknownAlgorithm, nil, errors.New("missing x-amz-copy-source​-server-side​-encryption​-customer-algorithm")
	}
	bas64Key := metadata["x-amz-copy-source​-server-side​-encryption​-customer-key"]
	if bas64Key == "" {
		return bitrot.UnknownAlgorithm, nil, errors.New("missing x-amz-copy-source​-server-side​-encryption​-customer-key")
	}
	bas64KeyMD5 := metadata["x-amz-copy-source-​server-side​-encryption​-customer-key-MD5"]
	if bas64Key == "" {
		return bitrot.UnknownAlgorithm, nil, errors.New("missing x-amz-copy-source-​server-side​-encryption​-customer-key-MD5")
	}
	alg = bitrot.ChaCha20Poly1305
	if bitrot.AESGCM.Available() {
		alg = bitrot.AESGCM
	}
	key, err = base64.StdEncoding.DecodeString(bas64Key)
	if err != nil {
		return bitrot.UnknownAlgorithm, nil, err
	}
	keyMD5, err := base64.StdEncoding.DecodeString(bas64KeyMD5)
	if err != nil {
		return bitrot.UnknownAlgorithm, nil, err
	}
	if len(key) != 32 { // SSE-Keys must be 256 bit
		return bitrot.UnknownAlgorithm, nil, errors.New("server-side-encryption key is not 256 long")
	}
	if sum := md5.Sum(key); subtle.ConstantTimeCompare(sum[:], keyMD5) != 1 {
		return bitrot.UnknownAlgorithm, nil, errors.New("server-side-encryption key does not match MD5 checksum")
	}
	return alg, key, nil
}

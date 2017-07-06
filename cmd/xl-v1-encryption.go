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
	ssePrefix     = "X-Amz-Server-Side-Encryption-Customer-"
	sseCopyPrefix = "X-Amz-Copy-Source​-Server-Side​-Encryption​-Customer-"

	sseAlgorithm      = ssePrefix + "Algorithm"
	sseCustomerKey    = ssePrefix + "Key"
	sseCustomerKeyMD5 = ssePrefix + "Key-Md5"

	sseCopyAlgorithm      = sseCopyPrefix + "Algorithm"
	sseCopyCustomerKey    = sseCopyPrefix + "Key"
	sseCopyCustomerKeyMD5 = sseCopyPrefix + "Key-Md5"
)

var sseHeaders = [...]string{sseAlgorithm, sseCopyAlgorithm, sseCustomerKey, sseCopyCustomerKey, sseCustomerKeyMD5, sseCopyCustomerKeyMD5}

// ServerSideEncryptionInfo contains the algorithm and the client provided
// secret key for server-side-encryption (SSE-C)
type ServerSideEncryptionInfo struct {
	Algorithm bitrot.Algorithm
	SecretKey []byte
}

func isServerSideEncryptonRequest(metadata map[string]string) bool {
	for _, header := range sseHeaders {
		if _, ok := metadata[header]; ok {
			return ok
		}
	}
	return false
}

// IsEncrypted retruns true if the object which is referenced by the metadata is encrypted.
func (xl *xlMetaV1) IsEncrypted() bool { return xl.Encryption != nil }

// VerifyClientKey takes the client-provided encryption info and verifies that the
// provided key can be used to decrypt the object. It retruns an error if the provided
// encryption info cannot be used to decrypt the referenced object.
func (xl *xlMetaV1) VerifyClientKey(encInfo *ServerSideEncryptionInfo) error {
	if encInfo == nil {
		return traceError(errors.New("failed to verify client key: no key provided"))
	}
	if !encInfo.Algorithm.IsCipher() {
		return Errorf("failed to verify client key: algorithm %s is not a cipher", encInfo.Algorithm)
	}
	if len(encInfo.SecretKey) != 32 {
		return Errorf("failed to verify client key: bad secret key size: got: #%d , want: #%d", len(encInfo.SecretKey), 32)
	}
	if !xl.IsEncrypted() {
		return traceError(errors.New("failed to verify client key: object is not encrypted"))
	}

	if encInfo.Algorithm.String() != xl.Encryption.Algorithm {
		return Errorf("failed to verify client key: algorithm mismatch: got: %s , want: %s", encInfo.Algorithm, xl.Encryption.Algorithm)
	}

	hash, err := hex.DecodeString(xl.Encryption.Hash)
	if err != nil {
		return traceError(err)
	}
	salt, err := hex.DecodeString(xl.Encryption.Salt)
	if err != nil {
		return traceError(err)
	}
	mac := hmac.New(sha256.New, encInfo.SecretKey)
	if _, err = mac.Write(salt); err != nil {
		return traceError(err)
	}
	if sum := mac.Sum(nil); subtle.ConstantTimeCompare(sum, hash) != 1 {
		return Errorf("failed to verify client key: HMAC mismatch: got: %s , want: %s", hex.EncodeToString(sum), hex.EncodeToString(hash))
	}
	return nil
}

// Encrypt encrypts the user-provided metadata and stores a HMAC hash of the client provided key
// in the XL metadata. It returns an error if the encryption process fails.
func (xl *xlMetaV1) Encrypt(random io.Reader, encInfo *ServerSideEncryptionInfo) error {
	if encInfo == nil {
		return traceError(errors.New("failed to encrypt metadata: no key provided"))
	}
	if !encInfo.Algorithm.IsCipher() {
		return Errorf("failed to encrypt metadata: algorithm %s is not a cipher", encInfo.Algorithm)
	}
	if len(encInfo.SecretKey) != 32 {
		return Errorf("failed to encrypt metadata: bad secret key size: got: #%d , want: #%d", len(encInfo.SecretKey), 32)
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(random, salt); err != nil {
		return traceError(err)
	}
	mac := hmac.New(sha256.New, encInfo.SecretKey)
	if _, err := mac.Write(salt); err != nil {
		return traceError(err)
	}
	hash := mac.Sum(nil)

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return traceError(err)
	}
	if keyLen := len(encInfo.SecretKey) + len(nonce); keyLen != encInfo.Algorithm.KeySize() {
		return Errorf("failed to decrypt metadata: bad key-nonce length: got #%d , want #%d", keyLen, encInfo.Algorithm.KeySize())
	}

	metaKey := make([]byte, encInfo.Algorithm.KeySize())
	copy(metaKey, nonce)
	copy(metaKey[len(nonce):], encInfo.SecretKey)

	cipher, err := encInfo.Algorithm.New(metaKey, bitrot.Verify)
	if err != nil {
		return traceError(err)
	}
	encMetadata := make(map[string]string, len(xl.Meta))
	for k, v := range xl.Meta {
		key, value := []byte(k), []byte(v)
		cipher.Write(key)
		cipher.Write(value)
		encMetadata[hex.EncodeToString(key)] = hex.EncodeToString(value)
	}
	xl.Meta = encMetadata
	xl.Encryption = &EncryptionInfo{
		Algorithm: encInfo.Algorithm.String(),
		Hash:      hex.EncodeToString(hash),
		Salt:      hex.EncodeToString(salt),
		MetaNonce: hex.EncodeToString(nonce),
		MetaTag:   hex.EncodeToString(cipher.Sum(nil)),
	}
	return nil
}

// Decrypt decrypts the user-provided metadata. It returns an error if the decryption process fails.
// The client provided key should be verified before.
func (xl *xlMetaV1) Decrypt(encInfo *ServerSideEncryptionInfo) error {
	if encInfo == nil {
		return traceError(errors.New("failed to decrypt metadata: no key provided"))
	}
	if !encInfo.Algorithm.IsCipher() {
		return Errorf("failed to decrypt metadata: algorithm %s is not a cipher", encInfo.Algorithm)
	}
	if len(encInfo.SecretKey) != 32 {
		return Errorf("failed to decrypt metadata: bad secret key size: got: #%d , want: #%d", len(encInfo.SecretKey), 32)
	}
	if encInfo.Algorithm.String() != xl.Encryption.Algorithm {
		return Errorf("failed to decrypt metadata: algorithm mismatch: got: %s , want: %s", encInfo.Algorithm, xl.Encryption.Algorithm)
	}
	if !xl.IsEncrypted() {
		return traceError(errors.New("failed to decrypt metadata: object is not encrypted"))
	}

	nonce, err := hex.DecodeString(xl.Encryption.MetaNonce)
	if err != nil {
		return traceError(err)
	}
	tag, err := hex.DecodeString(xl.Encryption.MetaTag)
	if err != nil {
		return traceError(err)
	}
	if keyLen := len(encInfo.SecretKey) + len(nonce); keyLen != encInfo.Algorithm.KeySize() {
		return Errorf("failed to decrypt metadata: bad key-nonce length: got #%d , want #%d", keyLen, encInfo.Algorithm.KeySize())
	}

	metaKey := make([]byte, encInfo.Algorithm.KeySize())
	copy(metaKey, nonce)
	copy(metaKey[len(nonce):], encInfo.SecretKey)

	cipher, err := encInfo.Algorithm.New(metaKey, bitrot.Verify)
	if err != nil {
		return traceError(err)
	}
	decMetadata := make(map[string]string, len(xl.Meta))
	for k, v := range xl.Meta {
		key, err := hex.DecodeString(k)
		if err != nil {
			return traceError(err)
		}
		value, err := hex.DecodeString(v)
		if err != nil {
			return traceError(err)
		}
		cipher.Write(key)
		cipher.Write(value)
		decMetadata[string(key)] = string(value)
	}
	if sum := cipher.Sum(nil); subtle.ConstantTimeCompare(sum, tag) != 1 {
		return traceError(errors.New("failed to decrypt metadata: authentication error"))
	}
	xl.Meta = decMetadata
	return nil
}

// ParseServerSideEncryptionInfo takes the client-provided headers and extracts the ServerSideEncryptionInfo.
// It returns an error if the client provided metadata does not contain a valid encryption request.
func ParseServerSideEncryptionInfo(metadata map[string]string) (info *ServerSideEncryptionInfo, err error) {
	var base64Key, base64KeyMD5 string
	// this is currently hardcoded by AWS - whatever you mean with "AES256", Amazon. ¯\_(ツ)_/¯
	if metadata[sseAlgorithm] != "AES256" {
		return info, Errorf("missing %s", sseAlgorithm)
	}
	base64Key = metadata[sseCustomerKey]
	if base64Key == "" {
		return info, Errorf("missing %s", sseCustomerKey)
	}
	base64KeyMD5 = metadata[sseCustomerKeyMD5]
	if base64Key == "" {
		return info, Errorf("missing %s", sseCustomerKeyMD5)
	}
	delete(metadata, sseAlgorithm)
	delete(metadata, sseCustomerKey)
	delete(metadata, sseCustomerKeyMD5)

	algorithm := bitrot.ChaCha20Poly1305
	if bitrot.AESGCM.Available() {
		algorithm = bitrot.AESGCM
	}
	secretKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return info, err
	}
	keyMD5, err := base64.StdEncoding.DecodeString(base64KeyMD5)
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

// ParseServerSideEncryptionCopyInfo takes the client-provided headers and extracts the ServerSideEncryptionInfo.
// It returns an error if the client provided metadata does not contain a valid encryption request.
func ParseServerSideEncryptionCopyInfo(metadata map[string]string) (info *ServerSideEncryptionInfo, err error) {
	var base64Key, base64KeyMD5 string
	// this is currently hardcoded by AWS - whatever you mean with "AES256", Amazon. ¯\_(ツ)_/¯
	if metadata[sseCopyAlgorithm] != "AES256" {
		return info, Errorf("missing %s", sseCopyAlgorithm)
	}
	base64Key = metadata[sseCopyCustomerKey]
	if base64Key == "" {
		return info, Errorf("missing %s", sseCopyCustomerKey)
	}
	base64KeyMD5 = metadata[sseCopyCustomerKeyMD5]
	if base64Key == "" {
		return info, Errorf("missing %s", sseCopyCustomerKeyMD5)
	}
	delete(metadata, sseCopyAlgorithm)
	delete(metadata, sseCopyCustomerKey)
	delete(metadata, sseCopyCustomerKeyMD5)

	algorithm := bitrot.ChaCha20Poly1305
	if bitrot.AESGCM.Available() {
		algorithm = bitrot.AESGCM
	}
	secretKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return info, err
	}
	keyMD5, err := base64.StdEncoding.DecodeString(base64KeyMD5)
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

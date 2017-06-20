package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"

	"net/http"

	"crypto/aes"
	"crypto/cipher"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/blake2b"
)

var supportedAlgorithms = map[string]bool{
	"AES256": true,
	// Add algorithms here
}

const (
	sseCustomerAlgorithm = "x-amz-server-side-encryption-customer-algorithm"
	sseCustomerKey       = "x-amz-server-side-encryption-customer-key"
	sseCustomerKeyMD5    = "x-amz-server-side-encryption-customer-key-MD5"
)

const (
	sseCopyCustomerAlgorithm = "x-amz-copy-source​-server-side​-encryption​-customer-algorithm"
	sseCopyCustomerKey       = "x-amz-copy-source​-server-side​-encryption​-customer-key"
	sseCopyCustomerKeyMD5    = "x-amz-copy-source-​server-side​-encryption​-customer-key-MD5"
)

func parseSSERequest(header http.Header) (key []byte, enc EncryptionConfig, err error) {
	alg := header.Get(sseCustomerAlgorithm)
	if alg == "" {
		err = errors.New("missing algorithm for server side encryption")
		return
	}
	if !supportedAlgorithms[alg] {
		err = errors.New("algorithm not supported for server side encryption")
		return
	}
	encKey := header.Get(sseCustomerKey)
	if encKey == "" {
		err = errors.New("missing key for server side encryption")
		return
	}
	/*
		encMD5 := header.Get(sseCustomerKeyMD5)
		if encMD5 == "" {
			err = errors.New("missing MD5 hash of key for server side encryption")
			return
		}
	*/
	// TODO(aead): verify that key matches MD5(key)
	key, err = base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return
	}
	HMAC := blake2b.Sum512(key)
	enc = EncryptionConfig{
		Algorithm: alg,
		Cipher:    "ChaCha20Poly1305",
		HMAC:      base64.StdEncoding.EncodeToString(HMAC[:]),
		MD5:       "",
	}
	return
}

func parseSSECopyRequest(header http.Header) (key []byte, enc EncryptionConfig, err error) {
	alg := header.Get(sseCopyCustomerAlgorithm)
	if alg == "" {
		err = errors.New("missing algorithm for server side encryption")
		return
	}
	if !supportedAlgorithms[alg] {
		err = errors.New("algorithm not supported for server side encryption")
		return
	}
	encKey := header.Get(sseCopyCustomerKey)
	if encKey == "" {
		err = errors.New("missing key for server side encryption")
		return
	}
	encMD5 := header.Get(sseCopyCustomerKeyMD5)
	if encMD5 == "" {
		err = errors.New("missing MD5 hash of key for server side encryption")
		return
	}
	// TODO(aead): verify that key matches MD5(key)
	key, err = base64.StdEncoding.DecodeString(encKey)
	if err != nil {
		return
	}
	HMAC := blake2b.Sum512(key)
	enc = EncryptionConfig{
		Algorithm: alg,
		Cipher:    "ChaCha20Poly1305",
		HMAC:      base64.StdEncoding.EncodeToString(HMAC[:]),
		MD5:       encMD5,
	}
	return
}

func (api objectAPIHandlers) GetEncryptedObjectHandler(w http.ResponseWriter, r *http.Request) {
	var object, bucket string
	vars := mux.Vars(r)
	bucket = vars["bucket"]
	object = vars["object"]

	// Fetch object stat info.
	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(w, ErrServerNotInitialized, r.URL)
		return
	}

	if s3Error := checkRequestAuthType(r, bucket, "s3:GetObject", serverConfig.GetRegion()); s3Error != ErrNone {
		writeErrorResponse(w, s3Error, r.URL)
		return
	}

	// Lock the object before reading.
	objectLock := globalNSMutex.NewNSLock(bucket, object)
	objectLock.RLock()
	defer objectLock.RUnlock()

	objInfo, err := objectAPI.GetObjectInfo(bucket, object)
	if err != nil {
		errorIf(err, "Unable to fetch object info.")
		apiErr := toAPIErrorCode(err)
		if apiErr == ErrNoSuchKey {
			apiErr = errAllowableObjectNotFound(bucket, r)
		}
		writeErrorResponse(w, apiErr, r.URL)
		return
	}

	// Get request range.
	var hrange *httpRange
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		if hrange, err = parseRequestRange(rangeHeader, objInfo.Size); err != nil {
			// Handle only errInvalidRange
			// Ignore other parse error and treat it as regular Get request like Amazon S3.
			if err == errInvalidRange {
				writeErrorResponse(w, ErrInvalidRange, r.URL)
				return
			}

			// log the error.
			errorIf(err, "Invalid request range")
		}
	}

	// Validate pre-conditions if any.
	if checkPreconditions(w, r, objInfo) {
		return
	}

	// Get the object.
	var startOffset int64
	length := objInfo.Size
	if hrange != nil {
		startOffset = hrange.offsetBegin
		length = hrange.getLength()
	}

	key, _, err := parseSSERequest(r.Header)
	errorIf(err, "Unable to write to client.")
	/*
		if !xlMeta.Encryption.CompareHMAC(encConfig.HMAC) {
			//return errors.New("invalid key")
		}
	*/

	decWriter, err := newDecryptedWriter(w, key)
	errorIf(err, "Unable to write to client.")

	// Indicates if any data was written to the http.ResponseWriter
	dataWritten := false
	// io.Writer type which keeps track if any data was written.
	writer := funcToWriter(func(p []byte) (int, error) {
		if !dataWritten {
			// Set headers on the first write.
			// Set standard object headers.
			setObjectHeaders(w, objInfo, hrange)

			// Set any additional requested response headers.
			setGetRespHeaders(w, r.URL.Query())

			dataWritten = true
		}
		return decWriter.Write(p)
	})

	// Reads the object at startOffset and writes to mw.
	if err = objectAPI.GetObject(bucket, object, startOffset, length, writer); err != nil {
		errorIf(err, "Unable to write to client.")
		if !dataWritten {
			// Error response only if no data has been written to client yet. i.e if
			// partial data has already been written before an error
			// occurred then no point in setting StatusCode and
			// sending error XML.
			writeErrorResponse(w, toAPIErrorCode(err), r.URL)
		}
		return
	}
	if !dataWritten {
		// If ObjectAPI.GetObject did not return error and no data has
		// been written it would mean that it is a 0-byte object.
		// call wrter.Write(nil) to set appropriate headers.
		writer.Write(nil)
	}
	//errorIf(decWriter.Close(), "Unable to write to client.")

	// Get host and port from Request.RemoteAddr.
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host, port = "", ""
	}

	// Notify object accessed via a GET request.
	eventNotify(eventData{
		Type:      ObjectAccessedGet,
		Bucket:    bucket,
		ObjInfo:   objInfo,
		ReqParams: extractReqParams(r),
		UserAgent: r.UserAgent(),
		Host:      host,
		Port:      port,
	})
}

func (api objectAPIHandlers) PutEncryptedObjectHandler(w http.ResponseWriter, r *http.Request) {
	objectAPI := api.ObjectAPI()
	if objectAPI == nil {
		writeErrorResponse(w, ErrServerNotInitialized, r.URL)
		return
	}

	// X-Amz-Copy-Source shouldn't be set for this call.
	if _, ok := r.Header["X-Amz-Copy-Source"]; ok {
		writeErrorResponse(w, ErrInvalidCopySource, r.URL)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object := vars["object"]

	// Get Content-Md5 sent by client and verify if valid
	md5Bytes, err := checkValidMD5(r.Header.Get("Content-Md5"))
	if err != nil {
		errorIf(err, "Unable to validate content-md5 format.")
		writeErrorResponse(w, ErrInvalidDigest, r.URL)
		return
	}

	/// if Content-Length is unknown/missing, deny the request
	size := r.ContentLength
	rAuthType := getRequestAuthType(r)
	if rAuthType == authTypeStreamingSigned {
		sizeStr := r.Header.Get("x-amz-decoded-content-length")
		size, err = strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			errorIf(err, "Unable to parse `x-amz-decoded-content-length` into its integer value", sizeStr)
			writeErrorResponse(w, toAPIErrorCode(err), r.URL)
			return
		}
	}
	if size == -1 {
		writeErrorResponse(w, ErrMissingContentLength, r.URL)
		return
	}

	/// maximum Upload size for objects in a single operation
	if isMaxObjectSize(size) {
		writeErrorResponse(w, ErrEntityTooLarge, r.URL)
		return
	}

	// Extract metadata to be saved from incoming HTTP header.
	metadata := extractMetadataFromHeader(r.Header)
	if rAuthType == authTypeStreamingSigned {
		if contentEncoding, ok := metadata["content-encoding"]; ok {
			contentEncoding = trimAwsChunkedContentEncoding(contentEncoding)
			if contentEncoding != "" {
				// Make sure to trim and save the content-encoding
				// parameter for a streaming signature which is set
				// to a custom value for example: "aws-chunked,gzip".
				metadata["content-encoding"] = contentEncoding
			} else {
				// Trimmed content encoding is empty when the header
				// value is set to "aws-chunked" only.

				// Make sure to delete the content-encoding parameter
				// for a streaming signature which is set to value
				// for example: "aws-chunked"
				delete(metadata, "content-encoding")
			}
		}
	}

	// Make sure we hex encode md5sum here.
	metadata["etag"] = hex.EncodeToString(md5Bytes)

	sha256sum := ""

	// Lock the object.
	objectLock := globalNSMutex.NewNSLock(bucket, object)
	objectLock.Lock()
	defer objectLock.Unlock()

	key, _, err := parseSSERequest(r.Header)
	if err != nil {
		errorIf(err, "Unable to write to client.")
	}
	/*
		if !xlMeta.Encryption.CompareHMAC(encConfig.HMAC) {
			//return errors.New("invalid key")
		}
	*/
	encReader, err := newEncryptedReader(r.Body, key)
	if err != nil {
		errorIf(err, "Unable to write to client.")
	}

	var objInfo ObjectInfo
	switch rAuthType {
	default:
		// For all unknown auth types return error.
		writeErrorResponse(w, ErrAccessDenied, r.URL)
		return
	case authTypeAnonymous:
		// http://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html
		if s3Error := enforceBucketPolicy(bucket, "s3:PutObject", r.URL.Path,
			r.Referer(), r.URL.Query()); s3Error != ErrNone {
			writeErrorResponse(w, s3Error, r.URL)
			return
		}
		// Create anonymous object.
		objInfo, err = objectAPI.PutObject(bucket, object, size, encReader, metadata, sha256sum)
	case authTypeStreamingSigned:
		// Initialize stream signature verifier.
		reader, s3Error := newSignV4ChunkedReader(r)
		if s3Error != ErrNone {
			errorIf(errSignatureMismatch, "%s", dumpRequest(r))
			writeErrorResponse(w, s3Error, r.URL)
			return
		}
		objInfo, err = objectAPI.PutObject(bucket, object, size, reader, metadata, sha256sum)
	case authTypeSignedV2, authTypePresignedV2:
		s3Error := isReqAuthenticatedV2(r)
		if s3Error != ErrNone {
			errorIf(errSignatureMismatch, "%s", dumpRequest(r))
			writeErrorResponse(w, s3Error, r.URL)
			return
		}
		objInfo, err = objectAPI.PutObject(bucket, object, size, encReader, metadata, sha256sum)
	case authTypePresigned, authTypeSigned:
		if s3Error := reqSignatureV4Verify(r, serverConfig.GetRegion()); s3Error != ErrNone {
			errorIf(errSignatureMismatch, "%s", dumpRequest(r))
			writeErrorResponse(w, s3Error, r.URL)
			return
		}
		if !skipContentSha256Cksum(r) {
			sha256sum = r.Header.Get("X-Amz-Content-Sha256")
		}
		// Create object.
		objInfo, err = objectAPI.PutObject(bucket, object, size, encReader, metadata, sha256sum)
	}
	if err != nil {
		errorIf(err, "Unable to create an object. %s", r.URL.Path)
		writeErrorResponse(w, toAPIErrorCode(err), r.URL)
		return
	}
	w.Header().Set("ETag", "\""+objInfo.ETag+"\"")
	writeSuccessResponseHeadersOnly(w)

	// Get host and port from Request.RemoteAddr.
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host, port = "", ""
	}

	// Notify object created event.
	eventNotify(eventData{
		Type:      ObjectCreatedPut,
		Bucket:    bucket,
		ObjInfo:   objInfo,
		ReqParams: extractReqParams(r),
		UserAgent: r.UserAgent(),
		Host:      host,
		Port:      port,
	})
}

func newEncryptedReader(r io.Reader, key []byte) (io.Reader, error) {
	nonce := blake2b.Sum256(key)
	//return chacha20poly1305.EncryptReader(r, key, nonce[:8])

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &aesCtrReader{
		c:   cipher.NewCTR(aesCipher, nonce[:16]),
		src: r,
	}, nil
}

func newDecryptedWriter(w io.Writer, key []byte) (io.Writer, error) {
	nonce := blake2b.Sum256(key)
	//return chacha20poly1305.DecryptWriter(w, key, nonce[:8])

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &aesCtrWriter{
		c:   cipher.NewCTR(aesCipher, nonce[:16]),
		dst: w,
	}, nil
}

type aesCtrWriter struct {
	c   cipher.Stream
	dst io.Writer
}

func (w *aesCtrWriter) Write(p []byte) (n int, err error) {
	w.c.XORKeyStream(p, p)
	return w.dst.Write(p)
}

type aesCtrReader struct {
	c   cipher.Stream
	src io.Reader
}

func (r *aesCtrReader) Read(p []byte) (n int, err error) {
	n, err = r.src.Read(p)
	r.c.XORKeyStream(p[:n], p[:n])
	return
}

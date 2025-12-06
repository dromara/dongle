// Package rsa implements RSA encryption, decryption, signing, and verification with streaming support.
// It provides RSA operations using the standard RSA algorithm with support
// for different key sizes and various padding schemes.
package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"hash"
	"io"

	"github.com/dromara/dongle/crypto/keypair"
)

type StdEncrypter struct {
	keypair keypair.RsaKeyPair
	Error   error
}

func NewStdEncrypter(kp *keypair.RsaKeyPair) *StdEncrypter {
	e := &StdEncrypter{
		keypair: *kp,
	}
	if len(kp.PublicKey) == 0 {
		e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
		return e
	}
	if kp.Padding == keypair.PSS {
		e.Error = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "PSS padding cannot be used for encryption"}}
		return e
	}
	return e
}

func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(src) == 0 {
		return
	}

	pubKey, err := e.keypair.ParsePublicKey()
	if err != nil {
		e.Error = EncryptError{Err: err}
		return nil, e.Error
	}

	format, padding := e.keypair.Format, e.keypair.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.OAEP
	}
	switch padding {
	case keypair.PKCS1v15:
		dst, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, src)
	case keypair.OAEP:
		dst, err = rsa.EncryptOAEP(e.keypair.Hash.New(), rand.Reader, pubKey, src, nil)
	case "":
		err = EncryptError{Err: keypair.EmptyPaddingError{}}
	default:
		err = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(padding)}}
	}

	if err != nil {
		e.Error = EncryptError{Err: err}
		return nil, e.Error
	}

	return dst, nil
}

type StdDecrypter struct {
	keypair keypair.RsaKeyPair // The key pair containing private key and format
	Error   error              // Error field for storing decryption errors
}

func NewStdDecrypter(kp *keypair.RsaKeyPair) *StdDecrypter {
	d := &StdDecrypter{
		keypair: *kp,
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
		return d
	}
	if kp.Padding == keypair.PSS {
		d.Error = DecryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "PSS padding cannot be used for decryption"}}
		return d
	}
	return d
}

func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Parse the private key from PEM format
	priKey, err := d.keypair.ParsePrivateKey()
	if err != nil {
		d.Error = DecryptError{Err: err}
		return nil, d.Error
	}

	format, padding := d.keypair.Format, d.keypair.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.OAEP
	}
	switch padding {
	case keypair.PKCS1v15:
		dst, err = rsa.DecryptPKCS1v15(rand.Reader, priKey, src)
	case keypair.OAEP:
		dst, err = rsa.DecryptOAEP(d.keypair.Hash.New(), rand.Reader, priKey, src, nil)
	case "":
		err = DecryptError{Err: keypair.EmptyPaddingError{}}
	default:
		err = DecryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(padding)}}
	}

	if err != nil {
		d.Error = DecryptError{Err: err}
		return nil, d.Error
	}

	return dst, nil
}

type StdSigner struct {
	keypair keypair.RsaKeyPair // The key pair containing private key and format
	Error   error              // Error field for storing signature errors
}

func NewStdSigner(kp *keypair.RsaKeyPair) *StdSigner {
	s := &StdSigner{
		keypair: *kp,
	}
	if len(kp.PrivateKey) == 0 {
		s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
		return s
	}
	if kp.Padding == keypair.OAEP {
		s.Error = SignError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "OAEP padding cannot be used for signing"}}
		return s
	}
	return s
}

func (s *StdSigner) Sign(src []byte) (sign []byte, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Parse the private key from PEM format
	priKey, err := s.keypair.ParsePrivateKey()
	if err != nil {
		s.Error = SignError{Err: err}
		return nil, s.Error
	}

	hasher := s.keypair.Hash.New()
	hasher.Write(src)
	hashed := hasher.Sum(nil)

	format, padding := s.keypair.Format, s.keypair.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.PSS
	}
	switch padding {
	case keypair.PKCS1v15:
		sign, err = rsa.SignPKCS1v15(rand.Reader, priKey, s.keypair.Hash, hashed)
	case keypair.PSS:
		sign, err = rsa.SignPSS(rand.Reader, priKey, s.keypair.Hash, hashed, nil)
	case "":
		err = SignError{Err: keypair.EmptyPaddingError{}}
	default:
		err = SignError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(padding)}}
	}

	if err != nil {
		s.Error = SignError{Err: err}
		return nil, s.Error
	}

	return sign, nil
}

type StdVerifier struct {
	keypair keypair.RsaKeyPair // The key pair containing public key and format
	Error   error              // Error field for storing verification errors
}

func NewStdVerifier(kp *keypair.RsaKeyPair) *StdVerifier {
	v := &StdVerifier{
		keypair: *kp,
	}
	if kp.Padding == keypair.OAEP {
		v.Error = VerifyError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "OAEP padding cannot be used for verification"}}
		return v
	}
	return v
}

func (v *StdVerifier) Verify(src, sign []byte) (valid bool, err error) {
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(src) == 0 {
		return
	}
	if len(sign) == 0 {
		err = VerifyError{Err: keypair.EmptySignatureError{}}
		return
	}
	pubKey, err := v.keypair.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return false, v.Error
	}

	hasher := v.keypair.Hash.New()
	hasher.Write(src)
	hashed := hasher.Sum(nil)

	format, padding := v.keypair.Format, v.keypair.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.PSS
	}
	switch padding {
	case keypair.PKCS1v15:
		err = rsa.VerifyPKCS1v15(pubKey, v.keypair.Hash, hashed, sign)
	case keypair.PSS:
		err = rsa.VerifyPSS(pubKey, v.keypair.Hash, hashed, sign, nil)
	case "":
		err = VerifyError{Err: keypair.EmptyPaddingError{}}
	default:
		err = VerifyError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(padding)}}
	}

	if err != nil {
		v.Error = VerifyError{Err: err}
		return false, v.Error
	}

	return true, nil
}

type StreamEncrypter struct {
	keypair   keypair.RsaKeyPair // Key pair containing padding and hash configuration
	pubKey    *rsa.PublicKey     // Cached public key for better performance
	writer    io.Writer          // Underlying writer for encrypted output
	hashFunc  func() hash.Hash   // Cached hash function for OAEP padding
	buffer    []byte             // Buffer to accumulate plaintext data
	chunkSize int                // Maximum plaintext chunk size for RSA encryption
	Error     error              // Error field for storing encryption errors
}

func NewStreamEncrypter(w io.Writer, kp *keypair.RsaKeyPair) io.WriteCloser {
	e := &StreamEncrypter{
		writer:  w,
		keypair: *kp,
	}
	if len(kp.PublicKey) == 0 {
		e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
		return e
	}
	if kp.Padding == keypair.PSS {
		e.Error = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "PSS padding cannot be used for encryption"}}
		return e
	}

	// Parse and cache the public key for reuse
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		e.Error = EncryptError{Err: err}
		return e
	}
	e.pubKey = pubKey

	format, padding := kp.Format, kp.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.OAEP
	}

	e.keypair.Padding = padding

	// Cache hash function for OAEP
	if padding == keypair.OAEP {
		e.hashFunc = kp.Hash.New
	}

	// Calculate maximum plaintext chunk size
	keySize := pubKey.Size()
	switch padding {
	case keypair.PKCS1v15:
		e.chunkSize = keySize - 11
	case keypair.OAEP:
		// OAEP padding overhead: 2*hashSize + 2
		hashSize := kp.Hash.Size()
		e.chunkSize = keySize - 2*hashSize - 2
	default:
		e.Error = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(padding)}}
		return e
	}

	e.buffer = make([]byte, 0, e.chunkSize)

	return e
}

func (e *StreamEncrypter) encrypt(data []byte) (encrypted []byte, err error) {
	if len(data) == 0 {
		return
	}

	// Use padding from keypair
	switch e.keypair.Padding {
	case keypair.PKCS1v15:
		encrypted, err = rsa.EncryptPKCS1v15(rand.Reader, e.pubKey, data)
	case keypair.OAEP:
		encrypted, err = rsa.EncryptOAEP(e.hashFunc(), rand.Reader, e.pubKey, data, nil)
	case "":
		err = EncryptError{Err: keypair.EmptyPaddingError{}}
	default:
		err = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(e.keypair.Padding)}}
	}

	if err != nil {
		e.Error = EncryptError{Err: err}
		return nil, e.Error
	}

	return encrypted, nil
}

func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Append incoming data to buffer
	e.buffer = append(e.buffer, p...)
	n = len(p)

	// Process complete chunks
	for len(e.buffer) >= e.chunkSize {
		// Extract one chunk
		chunk := e.buffer[:e.chunkSize]

		// Encrypt the chunk
		encrypted, encErr := e.encrypt(chunk)
		if encErr != nil {
			return 0, encErr
		}

		// Write encrypted data to the underlying writer
		if _, err = e.writer.Write(encrypted); err != nil {
			return 0, err
		}

		// Remove processed chunk from buffer
		e.buffer = e.buffer[e.chunkSize:]
	}

	return n, nil
}

func (e *StreamEncrypter) Close() error {
	// Check for existing errors
	if e.Error != nil {
		return e.Error
	}

	// Process any remaining data in the buffer
	if len(e.buffer) > 0 {
		// Encrypt the final chunk
		encrypted, err := e.encrypt(e.buffer)
		if err != nil {
			return err
		}

		// Write encrypted data to the underlying writer
		if _, err = e.writer.Write(encrypted); err != nil {
			return err
		}

		// Clear the buffer
		e.buffer = nil
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

type StreamDecrypter struct {
	keypair  keypair.RsaKeyPair // Key pair containing padding and hash configuration
	priKey   *rsa.PrivateKey    // Cached private key for better performance
	reader   io.Reader          // Underlying reader for encrypted input
	buffer   []byte             // Buffer for decrypted data
	position int                // Current position in buffer
	hashFunc func() hash.Hash   // Cached hash function for OAEP padding
	Error    error              // Error field for storing decryption errors
}

func NewStreamDecrypter(r io.Reader, kp *keypair.RsaKeyPair) io.Reader {
	d := &StreamDecrypter{
		keypair:  *kp,
		reader:   r,
		position: 0,
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
		return d
	}
	if kp.Padding == keypair.PSS {
		d.Error = DecryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "PSS padding cannot be used for decryption"}}
		return d
	}

	// Parse and cache the private key for reuse
	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		d.Error = DecryptError{Err: err}
		return d
	}
	d.priKey = priKey

	format, padding := kp.Format, kp.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.OAEP
	}

	d.keypair.Padding = padding

	// Cache hash function for OAEP
	if padding == keypair.OAEP {
		d.hashFunc = kp.Hash.New
	}

	return d
}

func (d *StreamDecrypter) decrypt(data []byte) (decrypted []byte, err error) {
	if len(data) == 0 {
		return
	}

	// Use padding from keypair
	switch d.keypair.Padding {
	case keypair.PKCS1v15:
		decrypted, err = rsa.DecryptPKCS1v15(rand.Reader, d.priKey, data)
	case keypair.OAEP:
		decrypted, err = rsa.DecryptOAEP(d.hashFunc(), rand.Reader, d.priKey, data, nil)
	case "":
		err = DecryptError{Err: keypair.EmptyPaddingError{}}
	default:
		err = DecryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(d.keypair.Padding)}}
	}

	if err != nil {
		d.Error = DecryptError{Err: err}
		return nil, d.Error
	}

	return decrypted, nil
}

func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}

	// If we have decrypted data available, return it
	if d.position < len(d.buffer) {
		n = copy(p, d.buffer[d.position:])
		d.position += n
		return n, nil
	}

	// If we've exhausted all decrypted data, try to read more
	if d.position >= len(d.buffer) {
		// Use cached private key
		if d.priKey == nil {
			d.Error = DecryptError{Err: errors.New("private key not initialized")}
			return 0, d.Error
		}

		// Read one encrypted block from the underlying reader
		blockSize := d.priKey.Size()
		encryptedBlock := make([]byte, blockSize)
		_, readErr := io.ReadFull(d.reader, encryptedBlock)

		// Handle EOF and partial reads
		if readErr == io.EOF {
			return 0, io.EOF
		}
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			return 0, io.EOF
		}
		if readErr != nil {
			d.Error = ReadError{Err: readErr}
			return 0, d.Error
		}

		// Note: io.ReadFull guarantees bytesRead == blockSize when readErr == nil
		out, err := d.decrypt(encryptedBlock)
		if err != nil {
			return 0, err
		}

		// Store decrypted data and reset position
		d.buffer = out
		d.position = 0

		// Return decrypted data
		if len(d.buffer) > 0 {
			n = copy(p, d.buffer)
			d.position += n
			return n, nil
		}
	}

	return 0, io.EOF
}

type StreamSigner struct {
	keypair keypair.RsaKeyPair // Key pair containing padding and hash configuration
	priKey  *rsa.PrivateKey    // Cached private key for better performance
	writer  io.Writer          // Underlying writer for signature output
	hasher  hash.Hash          // Hash function for streaming data processing
	Error   error              // Error field for storing signature errors
}

func NewStreamSigner(w io.Writer, kp *keypair.RsaKeyPair) io.WriteCloser {
	s := &StreamSigner{
		keypair: *kp,
		writer:  w,
	}
	if len(kp.PrivateKey) == 0 {
		s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
		return s
	}
	if kp.Padding == keypair.OAEP {
		s.Error = SignError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "OAEP padding cannot be used for signing"}}
		return s
	}

	// Parse and cache the private key for reuse
	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		s.Error = SignError{Err: err}
		return s
	}
	s.priKey = priKey

	format, padding := kp.Format, kp.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.PSS
	}

	s.keypair.Padding = padding
	s.hasher = kp.Hash.New()

	return s
}

func (s *StreamSigner) sign(hashed []byte) (signature []byte, err error) {
	if len(hashed) == 0 {
		return
	}
	// Use padding and hash from keypair
	switch s.keypair.Padding {
	case keypair.PKCS1v15:
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.priKey, s.keypair.Hash, hashed)
	case keypair.PSS:
		signature, err = rsa.SignPSS(rand.Reader, s.priKey, s.keypair.Hash, hashed, nil)
	case "":
		err = SignError{Err: keypair.EmptyPaddingError{}}
	default:
		err = SignError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(s.keypair.Padding)}}
	}

	if err != nil {
		s.Error = SignError{Err: err}
		return nil, s.Error
	}

	return signature, nil
}

func (s *StreamSigner) Write(p []byte) (n int, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(p) == 0 {
		return
	}
	s.hasher.Write(p)
	return len(p), nil
}

func (s *StreamSigner) Close() error {
	if s.Error != nil {
		return s.Error
	}

	// Get the final hash sum from the hasher
	hashed := s.hasher.Sum(nil)

	// Generate signature for the hashed data
	signature, err := s.sign(hashed)
	if err != nil {
		return err
	}

	// Write signature to the underlying writer
	if _, err = s.writer.Write(signature); err != nil {
		return err
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

type StreamVerifier struct {
	keypair   keypair.RsaKeyPair // Key pair containing padding and hash configuration
	pubKey    *rsa.PublicKey     // Cached public key for better performance
	reader    io.Reader          // Underlying reader for data input
	hasher    hash.Hash          // Hash function for streaming data processing
	signature []byte             // Signature to verify
	verified  bool               // Whether verification has been performed
	Error     error              // Error field for storing verification errors
}

func NewStreamVerifier(r io.Reader, kp *keypair.RsaKeyPair) io.WriteCloser {
	v := &StreamVerifier{
		keypair: *kp,
		reader:  r,
	}
	if len(kp.PublicKey) == 0 {
		v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
		return v
	}
	if kp.Padding == keypair.OAEP {
		v.Error = VerifyError{Err: keypair.UnsupportedPaddingSchemeError{Padding: "OAEP padding cannot be used for verification"}}
		return v
	}

	// Parse and cache the public key for reuse
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return v
	}
	v.pubKey = pubKey

	format, padding := kp.Format, kp.Padding
	if format == keypair.PKCS1 && padding == "" {
		padding = keypair.PKCS1v15
	}
	if format == keypair.PKCS8 && padding == "" {
		padding = keypair.PSS
	}

	v.keypair.Padding = padding
	v.hasher = kp.Hash.New()

	return v
}

func (v *StreamVerifier) verify(hashed, signature []byte) (valid bool, err error) {
	if len(hashed) == 0 {
		return
	}

	// Use padding and hash from keypair
	switch v.keypair.Padding {
	case keypair.PKCS1v15:
		err = rsa.VerifyPKCS1v15(v.pubKey, v.keypair.Hash, hashed, signature)
	case keypair.PSS:
		err = rsa.VerifyPSS(v.pubKey, v.keypair.Hash, hashed, signature, nil)
	case "":
		err = VerifyError{Err: keypair.EmptyPaddingError{}}
	default:
		err = VerifyError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(v.keypair.Padding)}}
	}

	if err != nil {
		v.Error = VerifyError{Err: err}
		return false, v.Error
	}

	return true, nil
}

// Write processes data through the hash function for streaming verification
func (v *StreamVerifier) Write(p []byte) (n int, err error) {
	if v.Error != nil {
		err = v.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Process data through the hash function for streaming
	v.hasher.Write(p)
	return len(p), nil
}

// Close performs the final verification and closes the verifier
func (v *StreamVerifier) Close() error {
	if v.Error != nil {
		return v.Error
	}

	// Read signature data from the underlying reader
	var err error
	v.signature, err = io.ReadAll(v.reader)
	if err != nil {
		return ReadError{Err: err}
	}
	if len(v.signature) == 0 {
		return nil
	}

	// Get the final hash sum from the hasher
	hashed := v.hasher.Sum(nil)

	// Verify the signature using the hashed data
	if _, err = v.verify(hashed, v.signature); err != nil {
		return err
	}

	// Mark verification as completed
	v.verified = true

	// Close the underlying reader if it implements io.Closer
	if closer, ok := v.reader.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

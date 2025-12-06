// Package sm2 implements SM2 public key encryption, decryption, signing and verification
// with optional streaming helpers.
package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/crypto/keypair"
)

// StdEncrypter encrypts data using an SM2 public key.
// The ciphertext component order is derived from Sm2KeyPair.Order.
type StdEncrypter struct {
	keypair keypair.Sm2KeyPair
	Error   error
}

// NewStdEncrypter creates a new SM2 encrypter bound to the given key pair.
func NewStdEncrypter(kp *keypair.Sm2KeyPair) *StdEncrypter {
	e := &StdEncrypter{keypair: *kp}
	if len(kp.PublicKey) == 0 {
		e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
		return e
	}
	return e
}

// Encrypt encrypts data with SM2 public key.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		return nil, e.Error
	}
	if len(src) == 0 {
		return
	}
	pub, err := e.keypair.ParsePublicKey()
	if err != nil {
		e.Error = EncryptError{Err: err}
		return nil, e.Error
	}
	out, err := sm2.Encrypt(rand.Reader, pub, src, sm2.CipherOrder(string(e.keypair.Order)), e.keypair.Window)
	if err != nil {
		e.Error = EncryptError{Err: err}
		return nil, e.Error
	}
	return out, nil
}

// StdDecrypter decrypts data using an SM2 private key.
type StdDecrypter struct {
	keypair keypair.Sm2KeyPair
	Error   error
}

// NewStdDecrypter creates a new SM2 decrypter bound to the given key pair.
func NewStdDecrypter(kp *keypair.Sm2KeyPair) *StdDecrypter {
	d := &StdDecrypter{keypair: *kp}
	if len(kp.PrivateKey) == 0 {
		d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
		return d
	}
	return d
}

// Decrypt decrypts data with SM2 private key.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}
	if len(src) == 0 {
		return nil, nil
	}
	pri, err := d.keypair.ParsePrivateKey()
	if err != nil {
		d.Error = DecryptError{Err: err}
		return nil, d.Error
	}
	out, err := sm2.Decrypt(pri, src, sm2.CipherOrder(string(d.keypair.Order)), d.keypair.Window)
	if err != nil {
		d.Error = DecryptError{Err: err}
		return nil, d.Error
	}
	return out, nil
}

// StreamEncrypter buffers plaintext and writes SM2 ciphertext on Close.
type StreamEncrypter struct {
	writer  io.Writer
	keypair keypair.Sm2KeyPair
	pubKey  *ecdsa.PublicKey // Cached public key for better performance
	buffer  []byte
	Error   error
}

// NewStreamEncrypter returns a WriteCloser that encrypts all written data
// with the provided key pair and writes the ciphertext on Close.
func NewStreamEncrypter(w io.Writer, kp *keypair.Sm2KeyPair) io.WriteCloser {
	e := &StreamEncrypter{
		writer:  w,
		keypair: *kp,
		buffer:  make([]byte, 0),
	}
	if len(kp.PublicKey) == 0 {
		e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
		return e
	}

	// Parse and cache the public key for reuse
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		e.Error = EncryptError{Err: err}
		return e
	}
	e.pubKey = pubKey

	return e
}

// encrypt encrypts plaintext with SM2 public key.
func (e *StreamEncrypter) encrypt(data []byte) (encrypted []byte, err error) {
	if len(data) == 0 {
		return
	}

	encrypted, err = sm2.Encrypt(rand.Reader, e.pubKey, data, sm2.CipherOrder(string(e.keypair.Order)), e.keypair.Window)
	if err != nil {
		e.Error = EncryptError{Err: err}
		return nil, err
	}

	return encrypted, nil
}

// Write buffers plaintext to be encrypted.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	if len(p) == 0 {
		return 0, nil
	}
	e.buffer = append(e.buffer, p...)
	return len(p), nil
}

// Close encrypts the buffered plaintext and writes the ciphertext to the
// underlying writer. If the writer implements io.Closer, it is closed.
func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}
	if len(e.buffer) == 0 {
		if closer, ok := e.writer.(io.Closer); ok {
			return closer.Close()
		}
		return nil
	}
	// Encrypt and write
	out, err := e.encrypt(e.buffer)
	if err != nil {
		return err
	}
	if _, err := e.writer.Write(out); err != nil {
		return err
	}
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter reads all ciphertext from an io.Reader and exposes the
// decrypted plaintext via Read.
type StreamDecrypter struct {
	reader   io.Reader
	keypair  keypair.Sm2KeyPair
	priKey   *ecdsa.PrivateKey // Cached private key for better performance
	buffer   []byte
	position int
	Error    error
}

// NewStreamDecrypter creates a Reader that decrypts the entire input from r
// using the provided key pair, serving plaintext on subsequent Read calls.
func NewStreamDecrypter(r io.Reader, kp *keypair.Sm2KeyPair) io.Reader {
	d := &StreamDecrypter{
		reader:   r,
		keypair:  *kp,
		position: 0,
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
		return d
	}

	// Parse and cache the private key for reuse
	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		d.Error = DecryptError{Err: err}
		return d
	}
	d.priKey = priKey

	return d
}

// decrypt decrypts ciphertext with SM2 private key.
func (d *StreamDecrypter) decrypt(data []byte) (decrypted []byte, err error) {
	if len(data) == 0 {
		return
	}

	decrypted, err = sm2.Decrypt(d.priKey, data, sm2.CipherOrder(string(d.keypair.Order)), d.keypair.Window)
	if err != nil {
		d.Error = DecryptError{Err: err}
		return nil, d.Error
	}

	return decrypted, nil
}

// Read serves decrypted plaintext from the internal buffer.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}
	// Serve from buffer if available
	if d.position < len(d.buffer) {
		n = copy(p, d.buffer[d.position:])
		d.position += n
		if d.position >= len(d.buffer) {
			return n, io.EOF
		}
		return n, nil
	}
	// Otherwise, read all ciphertext and decrypt once
	enc, err := io.ReadAll(d.reader)
	if err != nil {
		d.Error = ReadError{Err: err}
		return 0, d.Error
	}
	if len(enc) == 0 {
		return 0, io.EOF
	}
	out, err := d.decrypt(enc)
	if err != nil {
		return 0, err
	}
	d.buffer = out
	d.position = 0
	// Return plaintext
	n = copy(p, d.buffer)
	d.position += n
	if d.position >= len(d.buffer) {
		return n, io.EOF
	}
	return n, nil
}

// StdSigner signs data using an SM2 private key.
type StdSigner struct {
	keypair keypair.Sm2KeyPair
	Error   error
}

// NewStdSigner creates a new SM2 signer bound to the given key pair.
func NewStdSigner(kp *keypair.Sm2KeyPair) *StdSigner {
	s := &StdSigner{keypair: *kp}
	if len(kp.PrivateKey) == 0 {
		s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
		return s
	}
	return s
}

// Sign generates an SM2 signature for the given data.
func (s *StdSigner) Sign(src []byte) (sign []byte, err error) {
	if s.Error != nil {
		return nil, s.Error
	}
	if len(src) == 0 {
		return
	}

	// Parse the private key
	pri, err := s.keypair.ParsePrivateKey()
	if err != nil {
		s.Error = SignError{Err: err}
		return nil, s.Error
	}

	// Sign the message (Sign internally calculates ZA and digest)
	sign, err = sm2.Sign(nil, pri, src, s.keypair.UID)
	if err != nil {
		s.Error = SignError{Err: err}
		return nil, s.Error
	}

	return sign, nil
}

// StdVerifier verifies data using an SM2 public key.
type StdVerifier struct {
	keypair keypair.Sm2KeyPair
	Error   error
}

// NewStdVerifier creates a new SM2 verifier bound to the given key pair.
func NewStdVerifier(kp *keypair.Sm2KeyPair) *StdVerifier {
	v := &StdVerifier{keypair: *kp}
	if len(kp.PublicKey) == 0 {
		v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
		return v
	}
	return v
}

// Verify verifies an SM2 signature for the given data.
func (v *StdVerifier) Verify(src, sign []byte) (valid bool, err error) {
	if v.Error != nil {
		return false, v.Error
	}
	if len(src) == 0 {
		return false, nil
	}
	if len(sign) == 0 {
		err = VerifyError{Err: keypair.EmptySignatureError{}}
		return false, err
	}

	// Parse the public key
	pub, err := v.keypair.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return false, v.Error
	}

	// Verify the signature (Verify internally calculates ZA and digest)
	valid = sm2.Verify(pub, src, v.keypair.UID, sign)
	if !valid {
		v.Error = VerifyError{Err: nil}
		return false, v.Error
	}

	return valid, nil
}

// StreamSigner buffers data and writes SM2 signature on Close.
type StreamSigner struct {
	writer  io.Writer
	keypair keypair.Sm2KeyPair
	priKey  *ecdsa.PrivateKey // Cached private key for better performance
	buffer  []byte
	Error   error
}

// NewStreamSigner returns a WriteCloser that signs all written data
// with the provided key pair and writes the signature on Close.
func NewStreamSigner(w io.Writer, kp *keypair.Sm2KeyPair) io.WriteCloser {
	s := &StreamSigner{
		writer:  w,
		keypair: *kp,
		buffer:  make([]byte, 0),
	}
	if len(kp.PrivateKey) == 0 {
		s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
		return s
	}

	// Parse and cache the private key for reuse
	priKey, err := kp.ParsePrivateKey()
	if err != nil {
		s.Error = SignError{Err: err}
		return s
	}
	s.priKey = priKey

	return s
}

// sign generates a signature for the given data.
func (s *StreamSigner) sign(data []byte) (signature []byte, err error) {
	if len(data) == 0 {
		return
	}

	// Sign the data (Sign internally calculates ZA and digest)
	signature, err = sm2.Sign(nil, s.priKey, data, s.keypair.UID)
	if err != nil {
		s.Error = SignError{Err: err}
		return nil, s.Error
	}

	return signature, nil
}

// Write buffers data to be signed.
func (s *StreamSigner) Write(p []byte) (n int, err error) {
	if s.Error != nil {
		return 0, s.Error
	}
	if len(p) == 0 {
		return 0, nil
	}
	s.buffer = append(s.buffer, p...)
	return len(p), nil
}

// Close signs the buffered data and writes the signature to the
// underlying writer. If the writer implements io.Closer, it is closed.
func (s *StreamSigner) Close() error {
	if s.Error != nil {
		return s.Error
	}
	if len(s.buffer) == 0 {
		if closer, ok := s.writer.(io.Closer); ok {
			return closer.Close()
		}
		return nil
	}
	// Sign the buffered data
	signature, err := s.sign(s.buffer)
	if err != nil {
		return err
	}
	// Write signature to the underlying writer
	if _, err = s.writer.Write(signature); err != nil {
		return err
	}
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamVerifier reads signature from an io.Reader and verifies data written to it.
type StreamVerifier struct {
	reader    io.Reader
	keypair   keypair.Sm2KeyPair
	pubKey    *ecdsa.PublicKey // Cached public key for better performance
	buffer    []byte
	signature []byte
	verified  bool
	Error     error
}

// NewStreamVerifier creates a WriteCloser that verifies data written to it
// using the signature read from the provided reader.
func NewStreamVerifier(r io.Reader, kp *keypair.Sm2KeyPair) io.WriteCloser {
	v := &StreamVerifier{
		reader:  r,
		keypair: *kp,
		buffer:  make([]byte, 0),
	}
	if len(kp.PublicKey) == 0 {
		v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
		return v
	}

	// Parse and cache the public key for reuse
	pubKey, err := kp.ParsePublicKey()
	if err != nil {
		v.Error = VerifyError{Err: err}
		return v
	}
	v.pubKey = pubKey

	return v
}

// verify verifies the signature for the given data.
func (v *StreamVerifier) verify(data, signature []byte) (valid bool, err error) {
	if len(data) == 0 || len(signature) == 0 {
		return false, nil
	}

	// Verify the signature (Verify internally calculates ZA and digest)
	valid = sm2.Verify(v.pubKey, data, v.keypair.UID, signature)
	if !valid {
		v.Error = VerifyError{Err: nil}
		return false, v.Error
	}

	return valid, nil
}

// Write buffers data for verification.
func (v *StreamVerifier) Write(p []byte) (n int, err error) {
	if v.Error != nil {
		return 0, v.Error
	}
	if len(p) == 0 {
		return 0, nil
	}
	v.buffer = append(v.buffer, p...)
	return len(p), nil
}

// Close reads the signature from the underlying reader and performs verification.
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

	// Verify the signature using the buffered data
	valid, err := v.verify(v.buffer, v.signature)
	if err != nil {
		return err
	}

	v.verified = valid

	// Close the underlying reader if it implements io.Closer
	if closer, ok := v.reader.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"io"

	"github.com/dromara/dongle/crypto/keypair"
)

type StdEncrypter struct {
	keypair *keypair.RsaKeyPair
	Error   error
}

func NewStdEncrypter(kp *keypair.RsaKeyPair) *StdEncrypter {
	e := &StdEncrypter{
		keypair: kp,
	}
	if kp == nil {
		e.Error = NilKeyPairError{}
		return e
	}
	if len(kp.PublicKey) == 0 {
		e.Error = KeyPairError{Err: keypair.InvalidPublicKeyError{}}
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
	if e.keypair.Format == keypair.PKCS1 {
		// Use PKCS1v15 padding for PKCS1 format
		dst, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, src)
	}
	if e.keypair.Format == keypair.PKCS8 {
		// Use OAEP padding for PKCS8 format (more secure)
		dst, err = rsa.EncryptOAEP(e.keypair.Hash.New(), rand.Reader, pubKey, src, nil)
	}
	return
}

type StdDecrypter struct {
	keypair *keypair.RsaKeyPair // The key pair containing private key and format
	Error   error               // Error field for storing decryption errors
}

func NewStdDecrypter(kp *keypair.RsaKeyPair) *StdDecrypter {
	d := &StdDecrypter{
		keypair: kp,
	}
	if kp == nil {
		d.Error = NilKeyPairError{}
		return d
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = KeyPairError{Err: keypair.InvalidPrivateKeyError{}}
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
	// Decrypt using appropriate padding based on key format
	if d.keypair.Format == keypair.PKCS1 {
		// Use PKCS1v15 padding for PKCS1 format
		dst, err = rsa.DecryptPKCS1v15(rand.Reader, priKey, src)
	}
	if d.keypair.Format == keypair.PKCS8 {
		// Use OAEP padding for PKCS8 format
		dst, err = rsa.DecryptOAEP(d.keypair.Hash.New(), rand.Reader, priKey, src, nil)
	}
	if err != nil {
		err = DecryptError{Err: err}
	}
	return
}

type StreamEncrypter struct {
	writer  io.Writer           // Underlying writer for encrypted output
	keypair *keypair.RsaKeyPair // The key pair containing public key and format
	Error   error               // Error field for storing encryption errors
}

func NewStreamEncrypter(w io.Writer, kp *keypair.RsaKeyPair) io.WriteCloser {
	e := &StreamEncrypter{
		writer:  w,
		keypair: kp,
	}
	if kp == nil {
		e.Error = NilKeyPairError{}
		return e
	}
	if len(kp.PublicKey) == 0 {
		e.Error = KeyPairError{Err: keypair.InvalidPublicKeyError{}}
	}
	return e
}

func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}

	if len(p) == 0 {
		return
	}

	pubKey, err := e.keypair.ParsePublicKey()
	var encrypted []byte
	if e.keypair.Format == keypair.PKCS1 {
		// Use PKCS1v15 padding for PKCS1 format
		encrypted, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, p)
	}
	if e.keypair.Format == keypair.PKCS8 {
		// Use OAEP padding for PKCS8 format (more secure)
		encrypted, err = rsa.EncryptOAEP(e.keypair.Hash.New(), rand.Reader, pubKey, p, nil)
	}

	// Write encrypted data to the underlying writer
	_, writeErr := e.writer.Write(encrypted)
	if writeErr != nil {
		return 0, writeErr
	}
	// Return the number of input bytes processed, not output bytes written
	return len(p), nil
}

func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type StreamDecrypter struct {
	reader  io.Reader // Underlying reader for encrypted input
	keypair *keypair.RsaKeyPair
	Error   error // Error field for storing decryption errors
}

func NewStreamDecrypter(r io.Reader, kp *keypair.RsaKeyPair) io.Reader {
	d := &StreamDecrypter{
		reader:  r,
		keypair: kp,
	}
	if kp == nil {
		d.Error = NilKeyPairError{}
		return d
	}
	if len(kp.PrivateKey) == 0 {
		d.Error = KeyPairError{Err: keypair.InvalidPrivateKeyError{}}
	}
	return d
}

func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		err = d.Error
		return
	}

	// Read encrypted data from the underlying reader
	// For RSA, we need to read the entire encrypted block
	encrypted, err := io.ReadAll(d.reader)
	if err != nil {
		err = ReadError{Err: err}
		return
	}

	if len(encrypted) == 0 {
		return 0, io.EOF
	}

	// Parse the private key
	priKey, err := d.keypair.ParsePrivateKey()
	var decrypted []byte
	if d.keypair.Format == keypair.PKCS1 {
		// Use PKCS1v15 padding for PKCS1 format
		decrypted, err = rsa.DecryptPKCS1v15(rand.Reader, priKey, encrypted)
	}
	if d.keypair.Format == keypair.PKCS8 {
		// Use OAEP padding for PKCS8 format
		decrypted, err = rsa.DecryptOAEP(d.keypair.Hash.New(), rand.Reader, priKey, encrypted, nil)
	}
	if err != nil {
		return 0, DecryptError{Err: err}
	}

	// Copy decrypted data to the provided buffer
	n = copy(p, decrypted)
	return
}

type StdSigner struct {
	keypair *keypair.RsaKeyPair // The key pair containing private key and format
	Error   error               // Error field for storing signature errors
}

func NewStdSigner(kp *keypair.RsaKeyPair) *StdSigner {
	s := &StdSigner{
		keypair: kp,
	}
	if kp == nil {
		s.Error = NilKeyPairError{}
		return s
	}
	if len(kp.PrivateKey) == 0 {
		s.Error = KeyPairError{Err: keypair.InvalidPrivateKeyError{}}
	}
	return s
}

func (s *StdSigner) Sign(src []byte) (sign []byte, err error) {
	// Check for existing errors from initialization
	if s.Error != nil {
		err = s.Error
		return
	}

	if len(src) == 0 {
		return
	}

	// Parse the private key from PEM format
	priKey, err := s.keypair.ParsePrivateKey()

	hasher := s.keypair.Hash.New()
	hasher.Write(src)
	hashed := hasher.Sum(nil)

	// Generate signature using appropriate padding based on key format
	if s.keypair.Format == keypair.PKCS1 {
		// Use PKCS1v15 padding for PKCS1 format
		sign, err = rsa.SignPKCS1v15(rand.Reader, priKey, s.keypair.Hash, hashed)
	}
	if s.keypair.Format == keypair.PKCS8 {
		// Use PSS padding for PKCS8 format (more secure)
		sign, err = rsa.SignPSS(rand.Reader, priKey, s.keypair.Hash, hashed, nil)
	}
	s.keypair.Sign = sign
	return
}

type StdVerifier struct {
	keypair *keypair.RsaKeyPair // The key pair containing public key and format
	Error   error               // Error field for storing verification errors
}

func NewStdVerifier(kp *keypair.RsaKeyPair) *StdVerifier {
	v := &StdVerifier{
		keypair: kp,
	}
	if kp == nil {
		v.Error = NilKeyPairError{}
		return v
	}
	if len(kp.PublicKey) == 0 {
		v.Error = KeyPairError{Err: keypair.InvalidPublicKeyError{}}
	}
	return v
}

func (v *StdVerifier) Verify(src, sign []byte) (valid bool, err error) {
	// Check for existing errors from initialization
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(src) == 0 || len(sign) == 0 {
		return
	}

	pubKey, err := v.keypair.ParsePublicKey()

	hasher := v.keypair.Hash.New()
	hasher.Write(src)
	hashed := hasher.Sum(nil)

	// Verify signature using appropriate padding based on key format
	if v.keypair.Format == keypair.PKCS1 {
		// Use PKCS1v15 padding for PKCS1 format
		err = rsa.VerifyPKCS1v15(pubKey, v.keypair.Hash, hashed, sign)
	}
	if v.keypair.Format == keypair.PKCS8 {
		// Use PSS padding for PKCS8 format
		err = rsa.VerifyPSS(pubKey, v.keypair.Hash, hashed, sign, nil)
	}

	if err != nil {
		err = VerifyError{Err: err}
	} else {
		valid = true
	}
	return
}

type StreamSigner struct {
	writer  io.Writer           // Underlying writer for signature output
	keypair *keypair.RsaKeyPair // The key pair containing private key and format
	hasher  hash.Hash           // Hash function for streaming data processing
	Error   error               // Error field for storing signature errors
}

func NewStreamSigner(w io.Writer, kp *keypair.RsaKeyPair) io.WriteCloser {
	s := &StreamSigner{
		writer:  w,
		keypair: kp,
	}

	if kp == nil {
		s.Error = NilKeyPairError{}
		return s
	}

	s.hasher = kp.Hash.New()

	if len(kp.PrivateKey) == 0 {
		s.Error = KeyPairError{Err: keypair.InvalidPrivateKeyError{}}
	}
	return s
}

func (s *StreamSigner) Write(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if s.Error != nil {
		err = s.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Process data through the hash function for streaming
	_, err = s.hasher.Write(p)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (s *StreamSigner) Close() error {
	if s.Error != nil {
		return s.Error
	}

	// Get the final hash sum from the hasher
	hashed := s.hasher.Sum(nil)

	// Generate signature for the hashed data
	signature, err := s.Sign(hashed)

	// Write signature to the underlying writer
	_, err = s.writer.Write(signature)
	if err != nil {
		return err
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

func (s *StreamSigner) Sign(hashed []byte) (signature []byte, err error) {
	// Parse the private key from PEM format
	priKey, err := s.keypair.ParsePrivateKey()
	if err != nil {
		err = KeyPairError{Err: err}
		return
	}

	// Use PKCS1v15 padding for PKCS1 format
	if s.keypair.Format == keypair.PKCS1 {
		signature, err = rsa.SignPKCS1v15(rand.Reader, priKey, s.keypair.Hash, hashed)
	}
	// Use PSS padding for PKCS8 format (more secure)
	if s.keypair.Format == keypair.PKCS8 {
		signature, err = rsa.SignPSS(rand.Reader, priKey, s.keypair.Hash, hashed, nil)
	}

	return
}

type StreamVerifier struct {
	reader    io.Reader           // Underlying reader for data input
	keypair   *keypair.RsaKeyPair // The key pair containing public key and format
	hasher    hash.Hash           // Hash function for streaming data processing
	signature []byte              // Signature to verify
	verified  bool                // Whether verification has been performed
	Error     error               // Error field for storing verification errors
}

// Write processes data through the hash function for streaming verification
func (v *StreamVerifier) Write(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if v.Error != nil {
		err = v.Error
		return
	}

	if len(p) == 0 {
		return
	}

	// Process data through the hash function for streaming
	_, err = v.hasher.Write(p)
	if err != nil {
		return 0, err
	}

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
	_, verifyErr := v.Verify(hashed, v.signature)
	if verifyErr != nil {
		return verifyErr
	}

	// Mark verification as completed
	v.verified = true

	// Close the underlying reader if it implements io.Closer
	if closer, ok := v.reader.(io.Closer); ok {
		return closer.Close()
	}

	return nil
}

func NewStreamVerifier(r io.Reader, kp *keypair.RsaKeyPair) io.WriteCloser {
	v := &StreamVerifier{
		reader:  r,
		keypair: kp,
	}

	if kp == nil {
		v.Error = NilKeyPairError{}
		return v
	}

	v.hasher = kp.Hash.New()

	if len(kp.PublicKey) == 0 {
		v.Error = KeyPairError{Err: keypair.InvalidPublicKeyError{}}
	}
	return v
}

func (v *StreamVerifier) Verify(hashed, signature []byte) (valid bool, err error) {
	// Parse the public key from PEM format
	pubKey, err := v.keypair.ParsePublicKey()
	if err != nil {
		err = KeyPairError{Err: err}
		return
	}

	// Use PKCS1v15 padding for PKCS1 format
	if v.keypair.Format == keypair.PKCS1 {
		err = rsa.VerifyPKCS1v15(pubKey, v.keypair.Hash, hashed, signature)
	}
	// Use PSS padding for PKCS8 format
	if v.keypair.Format == keypair.PKCS8 {
		err = rsa.VerifyPSS(pubKey, v.keypair.Hash, hashed, signature, nil)
	}
	if err == nil {
		valid = true
	}
	return
}

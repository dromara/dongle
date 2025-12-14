package rsa

import (
	"crypto/rand"
	"io"

	"github.com/dromara/dongle/crypto/internal/rsa"
	"github.com/dromara/dongle/crypto/keypair"
)

type StdEncrypter struct {
	keypair keypair.RsaKeyPair // The key pair containing private key and format
	cache   cache              // Cached keys and hash for better performance
	Error   error              // Error field for storing encryption errors
}

func NewStdEncrypter(kp *keypair.RsaKeyPair) *StdEncrypter {
	e := &StdEncrypter{
		keypair: *kp,
	}
	if e.keypair.Type == "" {
		e.keypair.Type = keypair.PublicKey
	}
	if e.keypair.Type == keypair.PublicKey {
		if len(e.keypair.PublicKey) == 0 {
			e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
			return e
		}
		pubKey, err := e.keypair.ParsePublicKey()
		if err != nil {
			e.Error = EncryptError{Err: err}
			return e
		}
		e.cache.pubKey = pubKey
	}

	if e.keypair.Type == keypair.PrivateKey {
		if len(e.keypair.PrivateKey) == 0 {
			e.Error = EncryptError{Err: keypair.EmptyPrivateKeyError{}}
			return e
		}
		priKey, err := e.keypair.ParsePrivateKey()
		if err != nil {
			e.Error = EncryptError{Err: err}
			return e
		}
		e.cache.priKey = priKey
	}

	if e.keypair.Format == keypair.PKCS1 && e.keypair.Padding == "" {
		e.keypair.Padding = keypair.PKCS1v15
	}
	if e.keypair.Format == keypair.PKCS8 && e.keypair.Padding == "" {
		e.keypair.Padding = keypair.OAEP
	}
	if e.keypair.Padding == "" {
		e.Error = EncryptError{Err: keypair.EmptyPaddingError{}}
		return e
	}
	if e.keypair.Padding == keypair.OAEP {
		e.cache.hash = kp.Hash.New()
	}
	if e.keypair.Padding == keypair.PSS {
		e.Error = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(e.keypair.Padding)}}
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
	switch {
	case e.keypair.Type == keypair.PublicKey && e.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.EncryptPKCS1v15WithPublicKey(rand.Reader, e.cache.pubKey, src)
	case e.keypair.Type == keypair.PublicKey && e.keypair.Padding == keypair.OAEP:
		dst, err = rsa.EncryptOAEPWithPublicKey(e.cache.hash, rand.Reader, e.cache.pubKey, src)
	case e.keypair.Type == keypair.PrivateKey && e.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.EncryptPKCS1v15WithPrivateKey(rand.Reader, e.cache.priKey, src)
	case e.keypair.Type == keypair.PrivateKey && e.keypair.Padding == keypair.OAEP:
		dst, err = rsa.EncryptOAEPWithPrivateKey(e.cache.hash, rand.Reader, e.cache.priKey, src)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(e.keypair.Padding)}
	}
	if err != nil {
		err = EncryptError{Err: err}
		return
	}
	return
}

type StreamEncrypter struct {
	keypair   keypair.RsaKeyPair // Key pair containing padding and hash configuration
	cache     cache              // Cached keys and hash for better performance
	writer    io.Writer          // Underlying writer for encrypted output
	buffer    []byte             // Buffer to accumulate plaintext data
	chunkSize int                // Maximum plaintext chunk size for RSA encryption
	Error     error              // Error field for storing encryption errors
}

func NewStreamEncrypter(w io.Writer, kp *keypair.RsaKeyPair) io.WriteCloser {
	e := &StreamEncrypter{
		writer:  w,
		keypair: *kp,
	}
	if e.keypair.Type == "" {
		e.keypair.Type = keypair.PublicKey
	}
	if e.keypair.Type == keypair.PublicKey {
		if len(e.keypair.PublicKey) == 0 {
			e.Error = EncryptError{Err: keypair.EmptyPublicKeyError{}}
			return e
		}
		pubKey, err := e.keypair.ParsePublicKey()
		if err != nil {
			e.Error = EncryptError{Err: err}
			return e
		}
		e.cache.pubKey = pubKey
	}

	if e.keypair.Type == keypair.PrivateKey {
		if len(e.keypair.PrivateKey) == 0 {
			e.Error = EncryptError{Err: keypair.EmptyPrivateKeyError{}}
			return e
		}
		priKey, err := e.keypair.ParsePrivateKey()
		if err != nil {
			e.Error = EncryptError{Err: err}
			return e
		}
		e.cache.priKey = priKey
	}

	if e.keypair.Format == keypair.PKCS1 && e.keypair.Padding == "" {
		e.keypair.Padding = keypair.PKCS1v15
	}
	if e.keypair.Format == keypair.PKCS8 && e.keypair.Padding == "" {
		e.keypair.Padding = keypair.OAEP
	}
	if e.keypair.Padding == "" {
		e.Error = EncryptError{Err: keypair.EmptyPaddingError{}}
		return e
	}
	if e.keypair.Padding == keypair.OAEP {
		e.cache.hash = kp.Hash.New()
	}
	if e.keypair.Padding == keypair.PSS {
		e.Error = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(e.keypair.Padding)}}
		return e
	}

	// Calculate maximum plaintext chunk size
	var keySize int
	if e.keypair.Type == keypair.PublicKey {
		keySize = e.cache.pubKey.Size()
	} else {
		keySize = e.cache.priKey.Size()
	}
	switch e.keypair.Padding {
	case keypair.PKCS1v15:
		e.chunkSize = keySize - 11
	case keypair.OAEP:
		// OAEP padding overhead: 2*hashSize + 2
		hashSize := kp.Hash.Size()
		e.chunkSize = keySize - 2*hashSize - 2
	default:
		e.Error = EncryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(e.keypair.Padding)}}
		return e
	}
	e.buffer = make([]byte, 0, e.chunkSize)
	return e
}

func (e *StreamEncrypter) encrypt(data []byte) (dst []byte, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(data) == 0 {
		return
	}
	switch {
	case e.keypair.Type == keypair.PublicKey && e.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.EncryptPKCS1v15WithPublicKey(rand.Reader, e.cache.pubKey, data)
	case e.keypair.Type == keypair.PublicKey && e.keypair.Padding == keypair.OAEP:
		dst, err = rsa.EncryptOAEPWithPublicKey(e.cache.hash, rand.Reader, e.cache.pubKey, data)
	case e.keypair.Type == keypair.PrivateKey && e.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.EncryptPKCS1v15WithPrivateKey(rand.Reader, e.cache.priKey, data)
	case e.keypair.Type == keypair.PrivateKey && e.keypair.Padding == keypair.OAEP:
		dst, err = rsa.EncryptOAEPWithPrivateKey(e.cache.hash, rand.Reader, e.cache.priKey, data)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(e.keypair.Padding)}
	}
	if err != nil {
		err = EncryptError{Err: err}
		return
	}
	return
}

func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}
	if len(p) == 0 {
		return
	}
	// Append incoming data to buffer
	e.buffer = append(e.buffer, p...)
	n = len(p)

	// Process complete chunks
	for len(e.buffer) >= e.chunkSize {
		// Extract one chunk
		chunk := e.buffer[:e.chunkSize]
		// Encrypt the chunk
		dst, encErr := e.encrypt(chunk)
		if encErr != nil {
			return 0, encErr
		}
		// Write encrypted data to the underlying writer
		if _, writeErr := e.writer.Write(dst); writeErr != nil {
			return 0, writeErr
		}
		// Remove processed chunk from buffer
		e.buffer = e.buffer[e.chunkSize:]
	}
	return
}

func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}
	// Process any remaining data in the buffer
	if len(e.buffer) > 0 {
		// Encrypt the final chunk
		dst, encErr := e.encrypt(e.buffer)
		if encErr != nil {
			return encErr
		}
		// Write encrypted data to the underlying writer
		if _, writeErr := e.writer.Write(dst); writeErr != nil {
			return writeErr
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

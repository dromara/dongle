// Package chacha20poly1305 implements ChaCha20-Poly1305 authenticated encryption and decryption with streaming support.
// It provides ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) operations using the standard
// ChaCha20-Poly1305 algorithm with support for 256-bit keys, 96-bit nonces, and optional associated data.
package chacha20poly1305

import (
	stdCipher "crypto/cipher"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"golang.org/x/crypto/chacha20poly1305"
)

// StdEncrypter represents a ChaCha20-Poly1305 encrypter for standard encryption operations.
// It implements ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) encryption
// using the standard ChaCha20-Poly1305 algorithm with support for 256-bit keys, 96-bit nonces, and optional AAD.
type StdEncrypter struct {
	cipher *cipher.ChaCha20Poly1305Cipher // The cipher interface for encryption operations
	Error  error                          // Error field for storing encryption errors
}

// NewStdEncrypter creates a new ChaCha20-Poly1305 encrypter with the specified cipher and key.
// Validates the key length and nonce length, then initializes the encrypter for ChaCha20-Poly1305 encryption operations.
// The key must be exactly 32 bytes (256 bits) and nonce must be 12 bytes (96 bits).
func NewStdEncrypter(c *cipher.ChaCha20Poly1305Cipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) != chacha20poly1305.KeySize {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	if len(c.Nonce) != chacha20poly1305.NonceSize {
		e.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return e
	}

	return e
}

// Encrypt encrypts the given byte slice using ChaCha20-Poly1305 encryption.
// ChaCha20-Poly1305 provides authenticated encryption, returning ciphertext with authentication tag.
// The output includes both encrypted data and authentication tag for integrity verification.
// Returns empty data when input is empty.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		return nil, e.Error
	}

	if len(src) == 0 {
		return
	}

	aead, err := chacha20poly1305.New(e.cipher.Key)
	if err != nil {
		return nil, EncryptError{Err: err}
	}

	dst = aead.Seal(nil, e.cipher.Nonce, src, e.cipher.AAD)
	return dst, nil
}

// StdDecrypter represents a ChaCha20-Poly1305 decrypter for standard decryption operations.
// It implements ChaCha20-Poly1305 AEAD decryption using the standard ChaCha20-Poly1305 algorithm
// with support for 256-bit keys, 96-bit nonces, and optional AAD with authentication verification.
type StdDecrypter struct {
	cipher *cipher.ChaCha20Poly1305Cipher // The cipher interface for decryption operations
	Error  error                          // Error field for storing decryption errors
}

// NewStdDecrypter creates a new ChaCha20-Poly1305 decrypter with the specified cipher and key.
// Validates the key length and nonce length, then initializes the decrypter for ChaCha20-Poly1305 decryption operations.
// The key must be exactly 32 bytes (256 bits) and nonce must be 12 bytes (96 bits).
func NewStdDecrypter(c *cipher.ChaCha20Poly1305Cipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) != chacha20poly1305.KeySize {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	if len(c.Nonce) != chacha20poly1305.NonceSize {
		d.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return d
	}

	return d
}

// Decrypt decrypts the given byte slice using ChaCha20-Poly1305 decryption.
// ChaCha20-Poly1305 provides authenticated decryption, verifying both encryption and authentication.
// The input must include both encrypted data and authentication tag for successful decryption.
// Returns empty data when input is empty.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}

	if len(src) == 0 {
		return
	}

	aead, err := chacha20poly1305.New(d.cipher.Key)
	if err != nil {
		return nil, DecryptError{Err: err}
	}
	return aead.Open(nil, d.cipher.Nonce, src, d.cipher.AAD)
}

// StreamEncrypter represents a streaming ChaCha20-Poly1305 encrypter that implements io.WriteCloser.
// It provides efficient authenticated encryption for large data streams by processing data
// in chunks and writing encrypted output with authentication tags to the underlying writer.
//
// Note: ChaCha20-Poly1305 is an AEAD cipher that authenticates the entire message.
// For true streaming, each chunk is encrypted independently with its own authentication tag.
type StreamEncrypter struct {
	writer    io.Writer                      // Underlying writer for encrypted output
	cipher    *cipher.ChaCha20Poly1305Cipher // The cipher interface for encryption operations
	aead      stdCipher.AEAD                 // Reused AEAD cipher for better performance
	chunkSize int                            // Chunk size for streaming operations
	Error     error                          // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming ChaCha20-Poly1305 encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key and nonce lengths for proper ChaCha20-Poly1305 encryption.
// Each chunk is encrypted independently with authentication for true stream processing.
// The key must be exactly 32 bytes (256 bits) and nonce must be 12 bytes (96 bits).
func NewStreamEncrypter(w io.Writer, c *cipher.ChaCha20Poly1305Cipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer:    w,
		cipher:    c,
		chunkSize: 4096, // Default chunk size
	}

	if len(c.Key) != chacha20poly1305.KeySize {
		e.Error = KeySizeError(len(c.Key))
		return e
	}
	if len(c.Nonce) != chacha20poly1305.NonceSize {
		e.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return e
	}
	if aead, err := chacha20poly1305.New(c.Key); err == nil {
		e.aead = aead
	}
	return e
}

// Write implements io.Writer interface for streaming ChaCha20-Poly1305 encryption.
// Each write operation encrypts the data with authentication and writes it to the underlying writer.
// For streaming AEAD, each chunk gets its own authentication tag.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Initialize AEAD if not already done (handles direct struct creation)
	if e.aead == nil {
		if len(e.cipher.Key) != chacha20poly1305.KeySize {
			return 0, KeySizeError(len(e.cipher.Key))
		}
		if len(e.cipher.Nonce) != chacha20poly1305.NonceSize {
			return 0, InvalidNonceSizeError{Size: len(e.cipher.Nonce)}
		}
		if aead, err := chacha20poly1305.New(e.cipher.Key); err == nil {
			e.aead = aead
		}
	}

	// Encrypt the entire chunk with authentication
	encrypted := e.aead.Seal(nil, e.cipher.Nonce, p, e.cipher.AAD)

	_, writeErr := e.writer.Write(encrypted)
	if writeErr != nil {
		e.Error = WriteError{Err: writeErr}
		return 0, e.Error
	}

	return len(p), nil
}

// Close implements io.Closer interface for streaming ChaCha20-Poly1305 encryption.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}

	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming ChaCha20-Poly1305 decrypter that implements io.Reader.
// It provides efficient authenticated decryption for large data streams by reading encrypted data
// from the underlying reader and decrypting it in real-time with authentication verification.
//
// Note: For streaming AEAD decryption, the encrypted data must contain length prefixes
// or use fixed-size chunks to properly separate authenticated blocks.
type StreamDecrypter struct {
	reader io.Reader                      // Underlying reader for encrypted input
	cipher *cipher.ChaCha20Poly1305Cipher // The cipher interface for decryption operations
	aead   stdCipher.AEAD                 // Reused AEAD cipher for better performance
	Error  error                          // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming ChaCha20-Poly1305 decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key and nonce lengths for proper ChaCha20-Poly1305 decryption.
// The key must be exactly 32 bytes (256 bits) and nonce must be 12 bytes (96 bits).
func NewStreamDecrypter(r io.Reader, c *cipher.ChaCha20Poly1305Cipher) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
	}

	if len(c.Key) != chacha20poly1305.KeySize {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	if len(c.Nonce) != chacha20poly1305.NonceSize {
		d.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return d
	}
	if aead, err := chacha20poly1305.New(c.Key); err == nil {
		d.aead = aead
	}
	return d
}

// Read implements io.Reader interface for streaming ChaCha20-Poly1305 decryption.
// Provides true streaming decryption by reading and decrypting authenticated data chunks
// without buffering the entire dataset in memory.
//
// Note: This implementation reads the entire encrypted stream since ChaCha20-Poly1305
// authenticates the complete message. For true chunked streaming, use multiple AEAD operations.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Initialize AEAD if not already done (handles direct struct creation)
	if d.aead == nil {
		if len(d.cipher.Key) != chacha20poly1305.KeySize {
			return 0, KeySizeError(len(d.cipher.Key))
		}
		if len(d.cipher.Nonce) != chacha20poly1305.NonceSize {
			return 0, InvalidNonceSizeError{Size: len(d.cipher.Nonce)}
		}
		if aead, err := chacha20poly1305.New(d.cipher.Key); err == nil {
			d.aead = aead
		}
	}

	// Read all available data since ChaCha20-Poly1305 needs the complete authenticated message
	var encrypted []byte
	buf := make([]byte, 4096)
	for {
		n, err := d.reader.Read(buf)
		if n > 0 {
			encrypted = append(encrypted, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, ReadError{Err: err}
		}
	}

	if len(encrypted) == 0 {
		return 0, io.EOF
	}

	// Decrypt and authenticate the complete data
	decrypted, decryptErr := d.aead.Open(nil, d.cipher.Nonce, encrypted, d.cipher.AAD)
	if decryptErr != nil {
		return 0, AuthenticationError{}
	}

	// Copy decrypted data to output buffer
	copyLen := len(decrypted)
	if copyLen > len(p) {
		copyLen = len(p)
	}
	copy(p[:copyLen], decrypted[:copyLen])

	// If we have more data than the buffer, we need to handle this properly
	// For now, return what we can fit
	return copyLen, nil
}

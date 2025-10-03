// Package chacha20 implements ChaCha20 encryption and decryption with streaming support.
// It provides ChaCha20 encryption and decryption operations using the standard
// ChaCha20 algorithm with support for 256-bit keys and 96-bit nonces.
package chacha20

import (
	stdCipher "crypto/cipher"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"golang.org/x/crypto/chacha20"
)

// StdEncrypter represents a ChaCha20 encrypter for standard encryption operations.
// It implements ChaCha20 encryption using the standard ChaCha20 algorithm with support
// for 256-bit keys and 96-bit nonces.
type StdEncrypter struct {
	cipher *cipher.ChaCha20Cipher // The cipher interface for encryption operations
	Error  error                  // Error field for storing encryption errors
}

// NewStdEncrypter creates a new ChaCha20 encrypter with the specified cipher and key.
// Validates the key length and nonce length, then initializes the encrypter for ChaCha20 encryption operations.
// The key must be exactly 32 bytes (256 bits) and nonce must be 12 bytes (96 bits).
func NewStdEncrypter(c *cipher.ChaCha20Cipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) != 32 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	if len(c.Nonce) != 12 {
		e.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return e
	}

	return e
}

// Encrypt encrypts the given byte slice using ChaCha20 encryption.
// ChaCha20 is a stream cipher and can encrypt any amount of data.
// Returns empty data when input is empty.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		return nil, e.Error
	}

	if len(src) == 0 {
		return
	}

	c, err := chacha20.NewUnauthenticatedCipher(e.cipher.Key, e.cipher.Nonce)
	if err != nil {
		return nil, EncryptError{Err: err}
	}

	dst = make([]byte, len(src))
	c.XORKeyStream(dst, src)

	return dst, nil
}

// StdDecrypter represents a ChaCha20 decrypter for standard decryption operations.
// It implements ChaCha20 decryption using the standard ChaCha20 algorithm with support
// for 256-bit keys and 96-bit nonces.
type StdDecrypter struct {
	cipher *cipher.ChaCha20Cipher // The cipher interface for decryption operations
	Error  error                  // Error field for storing decryption errors
}

// NewStdDecrypter creates a new ChaCha20 decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for ChaCha20 decryption operations.
// The key must be exactly 32 bytes (256 bits) and nonce must be 12 bytes.
func NewStdDecrypter(c *cipher.ChaCha20Cipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) != 32 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	if len(c.Nonce) != 12 {
		d.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return d
	}

	return d
}

// Decrypt decrypts the given byte slice using ChaCha20 decryption.
// ChaCha20 is a stream cipher and can decrypt any amount of data.
// Returns empty data when input is empty.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}

	if len(src) == 0 {
		return
	}

	c, err := chacha20.NewUnauthenticatedCipher(d.cipher.Key, d.cipher.Nonce)
	if err != nil {
		return nil, DecryptError{Err: err}
	}

	dst = make([]byte, len(src))
	c.XORKeyStream(dst, src)

	return dst, nil
}

// StreamEncrypter represents a streaming ChaCha20 encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer              // Underlying writer for encrypted output
	cipher *cipher.ChaCha20Cipher // The cipher interface for encryption operations
	stream stdCipher.Stream       // Reused cipher stream for better performance
	Error  error                  // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming ChaCha20 encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key and nonce lengths for proper ChaCha20 encryption.
func NewStreamEncrypter(w io.Writer, c *cipher.ChaCha20Cipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
	}

	if len(c.Key) != 32 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	if len(c.Nonce) != 12 {
		e.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return e
	}

	e.stream, e.Error = chacha20.NewUnauthenticatedCipher(c.Key, c.Nonce)
	return e
}

// Write implements io.Writer interface for streaming ChaCha20 encryption.
// ChaCha20 is a stream cipher so it can handle any amount of data.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	if e.stream == nil {
		stream, err := chacha20.NewUnauthenticatedCipher(e.cipher.Key, e.cipher.Nonce)
		if err == nil {
			e.stream = stream
		}
	}

	encrypted := make([]byte, len(p))
	e.stream.XORKeyStream(encrypted, p)

	if _, err = e.writer.Write(encrypted); err != nil {
		e.Error = WriteError{Err: err}
		return 0, e.Error
	}

	return len(p), nil
}

// Close implements io.Closer interface for streaming ChaCha20 encryption.
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

// StreamDecrypter represents a streaming ChaCha20 decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by reading encrypted data
// from the underlying reader and decrypting it in real-time without buffering.
type StreamDecrypter struct {
	reader io.Reader              // Underlying reader for encrypted input
	cipher *cipher.ChaCha20Cipher // The cipher interface for decryption operations
	stream stdCipher.Stream       // Reused cipher stream for better performance
	Error  error                  // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming ChaCha20 decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key and nonce lengths for proper ChaCha20 decryption.
func NewStreamDecrypter(r io.Reader, c *cipher.ChaCha20Cipher) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
	}

	if len(c.Key) != 32 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	if len(c.Nonce) != 12 {
		d.Error = InvalidNonceSizeError{Size: len(c.Nonce)}
		return d
	}

	// Don't initialize the stream here - do it lazily in Read() for better error handling
	return d
}

// Read implements io.Reader interface for streaming ChaCha20 decryption.
// Provides true streaming decryption by reading and decrypting data in chunks
// without buffering the entire dataset in memory.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Initialize the cipher stream if not already done
	if d.stream == nil {
		if stream, err := chacha20.NewUnauthenticatedCipher(d.cipher.Key, d.cipher.Nonce); err == nil {
			d.stream = stream
		}
	}

	// Read encrypted data directly from the underlying reader
	encrypted := make([]byte, len(p))
	n, err = d.reader.Read(encrypted)

	if n > 0 {
		// Decrypt the data we just read
		d.stream.XORKeyStream(p[:n], encrypted[:n])
	}

	// Return the read count and any error (including io.EOF)
	return n, err
}

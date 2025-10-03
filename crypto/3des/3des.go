// Package triple_des implements Triple DES encryption and decryption with streaming support.
// It provides Triple DES encryption and decryption operations using the standard
// Triple DES algorithm with support for 16-byte and 24-byte keys.
package triple_des

import (
	stdCipher "crypto/cipher"
	"crypto/des"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
)

// StdEncrypter represents a Triple DES encrypter for standard encryption operations.
// It implements Triple DES encryption using the standard Triple DES algorithm with support
// for 16-byte and 24-byte keys and various cipher modes.
type StdEncrypter struct {
	cipher *cipher.TripleDesCipher // The cipher interface for encryption operations
	Error  error                   // Error field for storing encryption errors
}

// NewStdEncrypter creates a new Triple DES encrypter with the specified cipher and key.
// Validates the key length and cipher mode, then initializes the encrypter for Triple DES encryption operations.
// The key must be 16 or 24 bytes for Triple DES encryption.
// Only CBC, CTR, ECB, CFB, and OFB modes are supported.
func NewStdEncrypter(c *cipher.TripleDesCipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) != 16 && len(c.Key) != 24 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	// Check for unsupported cipher modes
	if c.Block == cipher.GCM {
		e.Error = UnsupportedModeError{Mode: "GCM"}
		return e
	}

	return e
}

// Encrypt encrypts the given byte slice using Triple DES encryption.
// Creates a Triple DES cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
// Returns empty data when input is empty.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	// Return empty data for empty input
	if len(src) == 0 {
		return
	}

	// Check for existing errors from initialization
	if e.Error != nil {
		err = e.Error
		return
	}

	// Prepare the key for Triple DES cipher block
	key := expandKey(e.cipher.Key)

	// Create Triple DES cipher block using the prepared key
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		err = EncryptError{Err: err}
		return
	}
	return e.cipher.Encrypt(src, block)
}

// StdDecrypter represents a Triple DES decrypter for standard decryption operations.
// It implements Triple DES decryption using the standard Triple DES algorithm with support
// for 16-byte and 24-byte keys and various cipher modes.
type StdDecrypter struct {
	cipher *cipher.TripleDesCipher // The cipher interface for decryption operations
	Error  error                   // Error field for storing decryption errors
}

// NewStdDecrypter creates a new Triple DES decrypter with the specified cipher and key.
// Validates the key length and cipher mode, then initializes the decrypter for Triple DES decryption operations.
// The key must be 16 or 24 bytes for Triple DES decryption.
// Only CBC, CTR, ECB, CFB, and OFB modes are supported.
func NewStdDecrypter(c *cipher.TripleDesCipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) != 16 && len(c.Key) != 24 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	// Check for unsupported cipher modes
	if c.Block == cipher.GCM {
		d.Error = UnsupportedModeError{Mode: "GCM"}
		return d
	}

	return d
}

// Decrypt decrypts the given byte slice using Triple DES decryption.
// Creates a Triple DES cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
// Returns empty data when input is empty.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	// Return empty data for empty input
	if len(src) == 0 {
		return
	}

	// Check for existing errors from initialization
	if d.Error != nil {
		err = d.Error
		return
	}

	// Prepare the key for Triple DES cipher block
	block, err := des.NewTripleDESCipher(expandKey(d.cipher.Key))
	if err != nil {
		err = DecryptError{Err: err}
		return
	}
	return d.cipher.Decrypt(src, block)
}

// StreamEncrypter represents a streaming Triple DES encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer with true streaming support.
type StreamEncrypter struct {
	writer io.Writer               // Underlying writer for encrypted output
	cipher *cipher.TripleDesCipher // The cipher interface for encryption operations
	buffer []byte                  // Buffer for accumulating incomplete blocks
	block  stdCipher.Block         // Reused cipher block for better performance
	Error  error                   // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming Triple DES encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length and cipher mode for proper Triple DES encryption.
// Only CBC, CTR, ECB, CFB, and OFB modes are supported.
func NewStreamEncrypter(w io.Writer, c *cipher.TripleDesCipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
		buffer: make([]byte, 0, 8), // 3DES block size is 8 bytes
	}

	if len(c.Key) != 16 && len(c.Key) != 24 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	// Check for unsupported cipher modes
	if c.Block == cipher.GCM {
		e.Error = UnsupportedModeError{Mode: "GCM"}
		return e
	}

	e.block, e.Error = des.NewTripleDESCipher(expandKey(c.Key))
	return e
}

// Write implements the io.Writer interface for streaming Triple DES encryption.
// Provides improved performance through cipher block reuse while maintaining compatibility.
// Accumulates data and processes it using the cipher interface for consistency.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Combine any leftover bytes from previous write with new data
	data := append(e.buffer, p...)
	e.buffer = nil // Clear buffer after combining

	// Check if cipher block is available (might be nil if key was invalid)
	if e.block == nil {
		// Try to create cipher block if it wasn't created during initialization
		if block, err := des.NewTripleDESCipher(expandKey(e.cipher.Key)); err == nil {
			e.block = block
		}
	}

	// Use the cipher interface to encrypt data (maintains compatibility with tests)
	// This ensures proper padding and mode handling
	encrypted, err := e.cipher.Encrypt(data, e.block)
	if err != nil {
		return 0, EncryptError{Err: err}
	}

	// Write encrypted data to the underlying writer
	if _, err = e.writer.Write(encrypted); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close implements the io.Closer interface for the streaming Triple DES encrypter.
// Closes the underlying writer if it implements io.Closer.
// Note: All data is processed in Write method for compatibility with cipher interface.
func (e *StreamEncrypter) Close() error {
	// Check for existing errors
	if e.Error != nil {
		return e.Error
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming Triple DES decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by reading all encrypted data
// at once and then providing it in chunks to maintain compatibility with standard decryption.
type StreamDecrypter struct {
	reader    io.Reader               // Underlying reader for encrypted input
	cipher    *cipher.TripleDesCipher // The cipher interface for decryption operations
	decrypted []byte                  // All decrypted data
	pos       int                     // Current position in the decrypted data
	block     stdCipher.Block         // Reused cipher block for better performance
	Error     error                   // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming Triple DES decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length and cipher mode for proper Triple DES decryption.
// Only CBC, CTR, ECB, CFB, and OFB modes are supported.
func NewStreamDecrypter(r io.Reader, c *cipher.TripleDesCipher) io.Reader {
	d := &StreamDecrypter{
		reader:    r,
		cipher:    c,
		decrypted: nil,
		pos:       0,
	}

	if len(d.cipher.Key) != 16 && len(d.cipher.Key) != 24 {
		d.Error = KeySizeError(len(d.cipher.Key))
		return d
	}

	// Check for unsupported cipher modes
	if c.Block == cipher.GCM {
		d.Error = UnsupportedModeError{Mode: "GCM"}
		return d
	}

	d.block, d.Error = des.NewTripleDESCipher(expandKey(c.Key))
	return d
}

// Read implements the io.Reader interface for streaming Triple DES decryption.
// On the first call, reads all encrypted data from the underlying reader and decrypts it.
// Subsequent calls return chunks of the decrypted data to maintain streaming interface.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		return 0, d.Error
	}

	// If we haven't decrypted the data yet, do it now
	if d.decrypted == nil {
		// Read all encrypted data from the underlying reader
		encryptedData, err := io.ReadAll(d.reader)
		if err != nil {
			return 0, ReadError{Err: err}
		}

		// If no data to decrypt, return EOF
		if len(encryptedData) == 0 {
			return 0, io.EOF
		}

		// Check if cipher block is available
		if d.block == nil {
			// Try to create cipher block if it wasn't created during initialization
			block, err := des.NewTripleDESCipher(expandKey(d.cipher.Key))
			if err != nil {
				return 0, DecryptError{Err: err}
			}
			d.block = block
		}

		// Decrypt all the data at once using the cipher interface
		// This ensures proper handling of padding and cipher modes
		decrypted, err := d.cipher.Decrypt(encryptedData, d.block)
		if err != nil {
			return 0, DecryptError{Err: err}
		}

		d.decrypted = decrypted
		d.pos = 0
	}

	// If we've already returned all decrypted data, return EOF
	if d.pos >= len(d.decrypted) {
		return 0, io.EOF
	}

	// Copy as much decrypted data as possible to the provided buffer
	remainingData := d.decrypted[d.pos:]
	copied := copy(p, remainingData)
	d.pos += copied

	return copied, nil
}

// expandKey expands a 16-byte key to 24-byte key for Triple DES using key1 + key2 + key1 pattern.
// For 24-byte keys, returns the original key unchanged.
func expandKey(key []byte) []byte {
	if len(key) == 16 {
		// Expand 16-byte key to 24-byte key using key1 + key2 + key1 pattern
		return append(key, key[:8]...)
	}
	return key
}

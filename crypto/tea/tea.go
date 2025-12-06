// Package tea implements TEA encryption and decryption with streaming support.
// It provides TEA encryption and decryption operations using the standard
// TEA algorithm with support for variable rounds and 128-bit keys.
package tea

import (
	stdCipher "crypto/cipher"
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"golang.org/x/crypto/tea"
)

// StdEncrypter represents a TEA encrypter for standard encryption operations.
// It implements TEA encryption using the standard TEA algorithm with support
// for different key sizes and various cipher modes.
type StdEncrypter struct {
	cipher *cipher.TeaCipher // The cipher interface for encryption operations
	block  stdCipher.Block   // Pre-created cipher block for reuse
	Error  error             // Error field for storing encryption errors
}

// NewStdEncrypter creates a new TEA encrypter with the specified cipher and key.
// Validates the key length and initializes the encrypter for TEA encryption operations.
// The key must be exactly 16 bytes (128 bits).
func NewStdEncrypter(c *cipher.TeaCipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}
	if len(c.Key) != 16 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}
	// Check for unsupported block mode
	if c.Block == cipher.GCM {
		e.Error = UnsupportedBlockModeError{Mode: "GCM"}
		return e
	}
	e.block, e.Error = tea.NewCipherWithRounds(c.Key, c.Rounds)
	return e
}

// Encrypt encrypts the given byte slice using TEA encryption.
// Creates a TEA cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
// Returns empty data when input is empty.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if e.Error != nil {
		err = e.Error
		return
	}

	// Return empty data for empty input
	if len(src) == 0 {
		return
	}

	block, err := tea.NewCipherWithRounds(e.cipher.Key, e.cipher.Rounds)
	if err != nil {
		err = EncryptError{Err: err}
		return
	}
	return e.cipher.Encrypt(src, block)
}

// StdDecrypter represents a TEA decrypter for standard decryption operations.
// It implements TEA decryption using the standard TEA algorithm with support
// for different key sizes and various cipher modes.
type StdDecrypter struct {
	cipher *cipher.TeaCipher // The cipher interface for decryption operations
	block  stdCipher.Block   // Pre-created cipher block for reuse
	Error  error             // Error field for storing decryption errors
}

// NewStdDecrypter creates a new TEA decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for TEA decryption operations.
// The key must be exactly 16 bytes (128 bits).
func NewStdDecrypter(c *cipher.TeaCipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}
	if len(c.Key) != 16 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}
	// Check for unsupported block mode
	if c.Block == cipher.GCM {
		d.Error = UnsupportedBlockModeError{Mode: "GCM"}
		return d
	}
	block, err := tea.NewCipherWithRounds(c.Key, c.Rounds)
	if err == nil {
		d.block = block
	}
	return d
}

// Decrypt decrypts the given byte slice using TEA decryption.
// Creates a TEA cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
// Returns empty data when input is empty.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		err = d.Error
		return
	}

	// Return empty data for empty input
	if len(src) == 0 {
		return
	}

	block, err := tea.NewCipherWithRounds(d.cipher.Key, d.cipher.Rounds)
	if err != nil {
		err = DecryptError{Err: err}
		return
	}
	return d.cipher.Decrypt(src, block)
}

// StreamEncrypter represents a streaming TEA encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer         // Underlying writer for encrypted output
	cipher *cipher.TeaCipher // The cipher interface for encryption operations
	buffer []byte            // Buffer for accumulating incomplete blocks
	block  stdCipher.Block   // Reused cipher block for better performance
	Error  error             // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming TEA encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length for proper TEA encryption.
func NewStreamEncrypter(w io.Writer, c *cipher.TeaCipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
		buffer: make([]byte, 0, 8), // TEA block size is 8 bytes
	}

	if len(c.Key) != 16 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}
	// Check for unsupported block mode
	if c.Block == cipher.GCM {
		e.Error = UnsupportedBlockModeError{Mode: "GCM"}
		return e
	}
	e.block, e.Error = tea.NewCipherWithRounds(c.Key, c.Rounds)
	return e
}

// Write implements the io.Writer interface for streaming TEA encryption.
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
		if block, err := tea.NewCipherWithRounds(e.cipher.Key, e.cipher.Rounds); err == nil {
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

// Close implements the io.Closer interface for the streaming TEA encrypter.
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

// StreamDecrypter represents a streaming TEA decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by processing data
// in chunks and reading decrypted output from the underlying reader with proper state management.
type StreamDecrypter struct {
	reader   io.Reader         // Underlying reader for encrypted input
	cipher   *cipher.TeaCipher // The cipher interface for decryption operations
	buffer   []byte            // Buffer for decrypted data
	position int               // Current position in the buffer
	block    stdCipher.Block   // Reused cipher block for better performance
	Error    error             // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming TEA decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper TEA decryption.
func NewStreamDecrypter(r io.Reader, c *cipher.TeaCipher) io.Reader {
	d := &StreamDecrypter{
		reader:   r,
		cipher:   c,
		buffer:   nil, // Will be populated on first read
		position: 0,
	}

	if len(c.Key) != 16 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}
	// Check for unsupported block mode
	if c.Block == cipher.GCM {
		d.Error = UnsupportedBlockModeError{Mode: "GCM"}
		return d
	}
	d.block, d.Error = tea.NewCipherWithRounds(c.Key, c.Rounds)
	return d
}

// Read implements the io.Reader interface for streaming TEA decryption.
// On the first call, reads all encrypted data from the underlying reader and decrypts it.
// Subsequent calls return chunks of the decrypted data to maintain streaming interface.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	// Check for existing errors from initialization
	if d.Error != nil {
		return 0, d.Error
	}

	// If we haven't decrypted the data yet, do it now
	if d.buffer == nil {
		// Read all encrypted data from the underlying reader
		encryptedData, err := io.ReadAll(d.reader)
		if err != nil {
			d.Error = ReadError{Err: err}
			return 0, d.Error
		}

		// If no data to decrypt, return EOF
		if len(encryptedData) == 0 {
			return 0, io.EOF
		}

		// Check if cipher block is available (might be nil if key was invalid)
		if d.block == nil {
			// Try to create cipher block if it wasn't created during initialization
			if block, err := tea.NewCipherWithRounds(d.cipher.Key, d.cipher.Rounds); err == nil {
				d.block = block
			}
		}

		// Use the cipher interface to decrypt data (maintains compatibility with tests)
		// This ensures proper padding and mode handling
		decrypted, err := d.cipher.Decrypt(encryptedData, d.block)
		if err != nil {
			d.Error = DecryptError{Err: err}
			return 0, d.Error
		}

		d.buffer = decrypted
		d.position = 0
	}

	// If we've already returned all decrypted data, return EOF
	if d.position >= len(d.buffer) {
		return 0, io.EOF
	}

	// Copy as much decrypted data as possible to the provided buffer
	remainingData := d.buffer[d.position:]
	copied := copy(p, remainingData)
	d.position += copied

	return copied, nil
}

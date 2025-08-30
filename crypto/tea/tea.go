// Package tea implements TEA encryption and decryption with streaming support.
// It provides TEA encryption and decryption operations using the standard
// TEA algorithm with support for variable rounds and 128-bit keys.
package tea

import (
	stdCipher "crypto/cipher"
	"io"

	"golang.org/x/crypto/tea"

	"github.com/dromara/dongle/crypto/cipher"
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

	// Try to pre-create cipher block for better performance
	// If there's an error, we'll handle it during Encrypt call
	block, err := tea.NewCipherWithRounds(c.Key, c.Rounds)
	if err == nil {
		e.block = block
	}
	// Don't set error here - let it be handled in Encrypt method

	return e
}

// Encrypt encrypts the given byte slice using TEA encryption.
// Uses the pre-created cipher block for better performance.
// TEA requires data to be a multiple of 8 bytes.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		return nil, e.Error
	}

	// TEA uses 8-byte blocks, data must be a multiple of 8 bytes
	if len(src)%8 != 0 {
		return nil, InvalidDataSizeError{Size: len(src)}
	}

	// Use pre-created cipher block for better performance
	if e.block == nil {
		// Fallback: create cipher block if not available
		block, err := tea.NewCipherWithRounds(e.cipher.Key, e.cipher.Rounds)
		if err != nil {
			return nil, EncryptError{Err: err}
		}
		e.block = block
	}

	// Encrypt each block
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += 8 {
		e.block.Encrypt(dst[i:i+8], src[i:i+8])
	}

	return dst, nil
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

	// Try to pre-create cipher block for better performance
	// If there's an error, we'll handle it during Decrypt call
	block, err := tea.NewCipherWithRounds(c.Key, c.Rounds)
	if err == nil {
		d.block = block
	}
	// Don't set error here - let it be handled in Decrypt method

	return d
}

// Decrypt decrypts the given byte slice using TEA decryption.
// Uses the pre-created cipher block for better performance.
// TEA requires data to be a multiple of 8 bytes.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}

	// TEA uses 8-byte blocks, data must be a multiple of 8 bytes
	if len(src)%8 != 0 {
		return nil, InvalidDataSizeError{Size: len(src)}
	}

	// Use pre-created cipher block for better performance
	if d.block == nil {
		// Fallback: create cipher block if not available
		block, err := tea.NewCipherWithRounds(d.cipher.Key, d.cipher.Rounds)
		if err != nil {
			return nil, DecryptError{Err: err}
		}
		d.block = block
	}

	// Decrypt each block
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += 8 {
		d.block.Decrypt(dst[i:i+8], src[i:i+8])
	}

	return dst, nil
}

// StreamEncrypter represents a streaming TEA encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer         // Underlying writer for encrypted output
	cipher *cipher.TeaCipher // The cipher interface for encryption operations
	block  stdCipher.Block   // Pre-created cipher block for reuse
	buffer []byte            // Buffer for accumulating incomplete blocks
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

	// Try to pre-create cipher block for better performance
	// If there's an error, we'll handle it during Write call
	block, err := tea.NewCipherWithRounds(c.Key, c.Rounds)
	if err == nil {
		e.block = block
	}
	// Don't set error here - let it be handled in Write method

	return e
}

// Write implements io.Writer interface for streaming TEA encryption.
// Provides improved performance through cipher block reuse and efficient buffering.
// Accumulates data in 8-byte blocks as required by TEA.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Check if cipher block is available
	if e.block == nil {
		// Fallback: create cipher block if not available
		block, err := tea.NewCipherWithRounds(e.cipher.Key, e.cipher.Rounds)
		if err != nil {
			e.Error = EncryptError{Err: err}
			return 0, e.Error
		}
		e.block = block
	}

	// For single write with non-block-aligned data, return error immediately
	// This maintains compatibility with existing tests that expect immediate validation
	if len(e.buffer) == 0 && len(p)%8 != 0 {
		return 0, InvalidDataSizeError{Size: len(p)}
	}

	// Combine any leftover bytes from previous write with new data
	data := append(e.buffer, p...)
	e.buffer = nil // Clear buffer after combining

	// Process complete 8-byte blocks
	blockSize := 8
	completeBlocks := len(data) / blockSize
	processedBytes := completeBlocks * blockSize

	if completeBlocks > 0 {
		// Encrypt complete blocks
		encrypted := make([]byte, processedBytes)
		for i := 0; i < processedBytes; i += blockSize {
			e.block.Encrypt(encrypted[i:i+blockSize], data[i:i+blockSize])
		}

		// Write encrypted data
		_, writeErr := e.writer.Write(encrypted)
		if writeErr != nil {
			e.Error = WriteError{Err: writeErr}
			return 0, e.Error
		}
	}

	// Store remaining bytes for next write
	if processedBytes < len(data) {
		e.buffer = append(e.buffer, data[processedBytes:]...)
	}

	return len(p), nil
}

// Close implements io.Closer interface for streaming TEA encryption.
// Processes any remaining buffered data and closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Process any remaining buffered data
	if len(e.buffer) > 0 {
		// TEA requires complete 8-byte blocks
		// In a real implementation, you might want to add padding here
		e.Error = InvalidDataSizeError{Size: len(e.buffer)}
		return e.Error
	}

	// Close the underlying writer if it implements io.Closer
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming TEA decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by reading encrypted data
// from the underlying reader and decrypting it in chunks.
type StreamDecrypter struct {
	reader    io.Reader         // Underlying reader for encrypted input
	cipher    *cipher.TeaCipher // The cipher interface for decryption operations
	decrypted []byte            // All decrypted data
	pos       int               // Current position in the decrypted data
	block     stdCipher.Block   // Pre-created cipher block for reuse
	Error     error             // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming TEA decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper TEA decryption.
func NewStreamDecrypter(r io.Reader, c *cipher.TeaCipher) io.Reader {
	d := &StreamDecrypter{
		reader:    r,
		cipher:    c,
		decrypted: nil, // Will be populated on first read
		pos:       0,
	}

	if len(c.Key) != 16 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	// Try to pre-create cipher block for better performance
	// If there's an error, we'll handle it during Read call
	block, err := tea.NewCipherWithRounds(c.Key, c.Rounds)
	if err == nil {
		d.block = block
	}
	// Don't set error here - let it be handled in Read method

	return d
}

// Read implements io.Reader interface for streaming TEA decryption.
// On the first call, reads all encrypted data from the underlying reader and decrypts it.
// Subsequent calls return chunks of the decrypted data to maintain streaming interface.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	// If we haven't decrypted the data yet, do it now
	if d.decrypted == nil {
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

		// Check if cipher block is available
		if d.block == nil {
			// Fallback: create cipher block if not available
			block, err := tea.NewCipherWithRounds(d.cipher.Key, d.cipher.Rounds)
			if err != nil {
				d.Error = DecryptError{Err: err}
				return 0, d.Error
			}
			d.block = block
		}

		// TEA uses 8-byte blocks, data must be a multiple of 8 bytes
		if len(encryptedData)%8 != 0 {
			// Return an error that suggests unexpected EOF (partial block read)
			d.Error = ReadError{Err: io.ErrUnexpectedEOF}
			return 0, d.Error
		}

		// Decrypt all the data at once
		decrypted := make([]byte, len(encryptedData))
		for i := 0; i < len(encryptedData); i += 8 {
			d.block.Decrypt(decrypted[i:i+8], encryptedData[i:i+8])
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

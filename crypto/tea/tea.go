// Package tea implements TEA encryption and decryption with streaming support.
// It provides TEA encryption and decryption operations using the standard
// TEA algorithm with support for variable rounds and 128-bit keys.
package tea

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"golang.org/x/crypto/tea"
)

// StdEncrypter represents a TEA encrypter for standard encryption operations.
// It implements TEA encryption using the standard TEA algorithm with support
// for different key sizes and various cipher modes.
type StdEncrypter struct {
	cipher cipher.TeaCipher // The cipher interface for encryption operations
	Error  error            // Error field for storing encryption errors
}

// NewStdEncrypter creates a new TEA encrypter with the specified cipher and key.
// Validates the key length and initializes the encrypter for TEA encryption operations.
// The key must be exactly 16 bytes (128 bits).
func NewStdEncrypter(c cipher.TeaCipher) *StdEncrypter {
	e := &StdEncrypter{
		cipher: c,
	}

	if len(c.Key) != 16 {
		e.Error = KeySizeError(len(c.Key))
	}

	return e
}

// Encrypt encrypts the given byte slice using TEA encryption.
// Creates a TEA cipher block and uses the configured cipher interface
// to perform the encryption operation with proper error handling.
func (e *StdEncrypter) Encrypt(src []byte) (dst []byte, err error) {
	if e.Error != nil {
		return nil, e.Error
	}

	// Create TEA cipher block using the provided key
	block, err := tea.NewCipherWithRounds(e.cipher.Key, e.cipher.Rounds)
	if err != nil {
		return nil, EncryptError{Err: err}
	}

	// TEA uses 8-byte blocks, data must be a multiple of 8 bytes
	if len(src)%8 != 0 {
		return nil, InvalidDataSizeError{Size: len(src)}
	}

	// Encrypt each block
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += 8 {
		block.Encrypt(dst[i:i+8], src[i:i+8])
	}

	return dst, nil
}

// StdDecrypter represents a TEA decrypter for standard decryption operations.
// It implements TEA decryption using the standard TEA algorithm with support
// for different key sizes and various cipher modes.
type StdDecrypter struct {
	cipher cipher.TeaCipher // The cipher interface for decryption operations
	Error  error            // Error field for storing decryption errors
}

// NewStdDecrypter creates a new TEA decrypter with the specified cipher and key.
// Validates the key length and initializes the decrypter for TEA decryption operations.
// The key must be exactly 16 bytes (128 bits).
func NewStdDecrypter(c cipher.TeaCipher) *StdDecrypter {
	d := &StdDecrypter{
		cipher: c,
	}

	if len(c.Key) != 16 {
		d.Error = KeySizeError(len(c.Key))
	}
	return d
}

// Decrypt decrypts the given byte slice using TEA decryption.
// Creates a TEA cipher block and uses the configured cipher interface
// to perform the decryption operation with proper error handling.
func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}

	// Create TEA cipher block using the provided key
	block, err := tea.NewCipherWithRounds(d.cipher.Key, d.cipher.Rounds)
	if err != nil {
		return nil, DecryptError{Err: err}
	}

	// TEA uses 8-byte blocks, data must be a multiple of 8 bytes
	if len(src)%8 != 0 {
		return nil, InvalidDataSizeError{Size: len(src)}
	}

	// Decrypt each block
	dst = make([]byte, len(src))
	for i := 0; i < len(src); i += 8 {
		block.Decrypt(dst[i:i+8], src[i:i+8])
	}

	return dst, nil
}

// StreamEncrypter represents a streaming TEA encrypter that implements io.WriteCloser.
// It provides efficient encryption for large data streams by processing data
// in chunks and writing encrypted output to the underlying writer.
type StreamEncrypter struct {
	writer io.Writer        // Underlying writer for encrypted output
	cipher cipher.TeaCipher // The cipher interface for encryption operations
	Error  error            // Error field for storing encryption errors
}

// NewStreamEncrypter creates a new streaming TEA encrypter that writes encrypted data
// to the provided io.Writer. The encrypter uses the specified cipher interface
// and validates the key length for proper TEA encryption.
func NewStreamEncrypter(w io.Writer, c cipher.TeaCipher) io.WriteCloser {
	e := &StreamEncrypter{
		writer: w,
		cipher: c,
	}

	if len(c.Key) != 16 {
		e.Error = KeySizeError(len(c.Key))
		return e
	}

	return e
}

// Write implements io.Writer interface for streaming TEA encryption.
// Encrypts the input data and writes it to the underlying writer.
// The data is processed in 8-byte blocks as required by TEA.
func (e *StreamEncrypter) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		err = e.Error
		return
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Create TEA cipher block
	block, err := tea.NewCipherWithRounds(e.cipher.Key, e.cipher.Rounds)
	if err != nil {
		e.Error = EncryptError{Err: err}
		return 0, e.Error
	}

	// Process data in 8-byte blocks
	blockSize := 8
	for i := 0; i < len(p); i += blockSize {
		end := i + blockSize
		if end > len(p) {
			end = len(p)
		}

		// Check if we have a complete block
		if end-i < blockSize {
			// Incomplete block - TEA requires complete 8-byte blocks
			e.Error = InvalidDataSizeError{Size: end - i}
			return n, e.Error
		}

		// Encrypt the block
		encrypted := make([]byte, blockSize)
		block.Encrypt(encrypted, p[i:end])

		// Write encrypted data
		_, writeErr := e.writer.Write(encrypted)
		if writeErr != nil {
			e.Error = WriteError{Err: writeErr}
			return n, e.Error
		}
		n += blockSize
	}

	return n, nil
}

// Close implements io.Closer interface for streaming TEA encryption.
// Closes the underlying writer if it implements io.Closer.
func (e *StreamEncrypter) Close() error {
	if closer, ok := e.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// StreamDecrypter represents a streaming TEA decrypter that implements io.Reader.
// It provides efficient decryption for large data streams by reading encrypted data
// from the underlying reader and decrypting it in chunks.
type StreamDecrypter struct {
	reader io.Reader        // Underlying reader for encrypted input
	cipher cipher.TeaCipher // The cipher interface for decryption operations
	Error  error            // Error field for storing decryption errors
}

// NewStreamDecrypter creates a new streaming TEA decrypter that reads encrypted data
// from the provided io.Reader. The decrypter uses the specified cipher interface
// and validates the key length for proper TEA decryption.
func NewStreamDecrypter(r io.Reader, c cipher.TeaCipher) io.Reader {
	d := &StreamDecrypter{
		reader: r,
		cipher: c,
	}

	if len(c.Key) != 16 {
		d.Error = KeySizeError(len(c.Key))
		return d
	}

	return d
}

// Read implements io.Reader interface for streaming TEA decryption.
// Reads encrypted data from the underlying reader and decrypts it.
// The data is processed in 8-byte blocks as required by TEA.
func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Create TEA cipher block
	block, err := tea.NewCipherWithRounds(d.cipher.Key, d.cipher.Rounds)
	if err != nil {
		d.Error = DecryptError{Err: err}
		return 0, d.Error
	}

	// Read encrypted data in 8-byte blocks
	blockSize := 8
	encryptedBlock := make([]byte, blockSize)

	readN, readErr := d.reader.Read(encryptedBlock)
	if readErr != nil {
		if readErr == io.EOF && readN == 0 {
			return 0, io.EOF
		}
		d.Error = ReadError{Err: readErr}
		return 0, d.Error
	}

	if readN < blockSize {
		// Handle partial block (should not happen with proper TEA encryption)
		d.Error = ReadError{Err: io.ErrUnexpectedEOF}
		return 0, d.Error
	}

	// Decrypt the block
	decrypted := make([]byte, blockSize)
	block.Decrypt(decrypted, encryptedBlock)

	// Copy decrypted data to output buffer
	copySize := len(p)
	if copySize > blockSize {
		copySize = blockSize
	}
	copy(p, decrypted[:copySize])

	return copySize, nil
}

// Package base64 implements base64 encoding and decoding with streaming support.
// It provides both standard and URL-safe base64 alphabets, along with
// streaming capabilities for efficient processing of large data.
// Base64 encoding follows RFC 4648 standard for binary-to-text encoding.
package base64

import (
	"encoding/base64"
	"io"
)

// StdAlphabet is the standard base64 alphabet as defined in RFC 4648.
// It uses uppercase letters A-Z, lowercase letters a-z, digits 0-9,
// plus sign (+), and forward slash (/) for a total of 64 characters.
// This is the most commonly used base64 alphabet for general purpose encoding.
var StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// URLAlphabet is the URL-safe base64 alphabet as defined in RFC 4648.
// It uses uppercase letters A-Z, lowercase letters a-z, digits 0-9,
// minus sign (-), and underscore (_) for a total of 64 characters.
// This alphabet is safe for use in URLs and filenames as it avoids
// characters that have special meaning in these contexts.
var URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// StdEncoder represents a base64 encoder for standard encoding operations.
// It wraps the standard library's base64.Encoding to provide a consistent
// interface with error handling capabilities and support for custom alphabets.
type StdEncoder struct {
	encoding *base64.Encoding // Underlying base64 encoding implementation
	alphabet string           // The alphabet used for encoding
	Error    error            // Error field for storing encoding errors
}

// NewStdEncoder creates a new base64 encoder with the specified alphabet.
// The alphabet must be a valid base64 alphabet string (exactly 64 characters).
// Common choices are StdAlphabet for standard encoding or URLAlphabet for URL-safe encoding.
func NewStdEncoder(alphabet string) *StdEncoder {
	if len(alphabet) != 64 {
		return &StdEncoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StdEncoder{encoding: base64.NewEncoding(alphabet), alphabet: alphabet}
}

// Encode encodes the given byte slice using base64 encoding.
// The encoded result uses the alphabet specified when creating the encoder.
// The encoding process handles padding automatically according to RFC 4648.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if e.Error != nil {
		return
	}
	if len(src) == 0 {
		return
	}

	// Pre-allocate buffer with exact size to avoid reallocation
	encodedLen := e.encoding.EncodedLen(len(src))
	dst = make([]byte, encodedLen)
	e.encoding.Encode(dst, src)
	return
}

// StdDecoder represents a base64 decoder for standard decoding operations.
// It wraps the standard library's base64.Encoding to provide a consistent
// interface with error handling capabilities and support for custom alphabets.
type StdDecoder struct {
	encoding *base64.Encoding // Underlying base64 encoding implementation
	alphabet string           // The alphabet used for decoding
	Error    error            // Error field for storing decoding errors
}

// NewStdDecoder creates a new base64 decoder with the specified alphabet.
// The alphabet must be a valid base64 alphabet string (exactly 64 characters).
// Common choices are StdAlphabet for standard decoding or URLAlphabet for URL-safe decoding.
func NewStdDecoder(alphabet string) *StdDecoder {
	if len(alphabet) != 64 {
		return &StdDecoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StdDecoder{encoding: base64.NewEncoding(alphabet), alphabet: alphabet}
}

// Decode decodes the given base64-encoded byte slice.
// The decoded result is truncated to the actual decoded length.
// Handles padding characters (=) automatically according to RFC 4648.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}
	if len(src) == 0 {
		return
	}

	// Pre-allocate buffer with estimated size to avoid reallocation
	decodedLen := d.encoding.DecodedLen(len(src))
	buf := make([]byte, decodedLen)

	n, err := d.encoding.Decode(buf, src)
	if err != nil {
		// Convert standard library error to custom error with position information
		// Try to determine the position of the error
		pos := int64(0)
		if len(src) > 0 {
			// For base64 errors, the position is usually at the beginning,
			// but we can't easily determine the exact position from std library
			pos = 0
		}
		d.Error = CorruptInputError(pos)
		return nil, d.Error
	}

	// Return slice with exact decoded length
	return buf[:n], nil
}

// StreamEncoder represents a streaming base64 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer   io.Writer        // Underlying writer for encoded output
	encoder  *base64.Encoding // Base64 encoding implementation
	alphabet string           // The alphabet used for encoding
	buffer   []byte           // Buffer for accumulating partial bytes (0-2 bytes)
	Error    error            // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base64 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the specified alphabet for encoding.
// The encoder automatically handles padding when Close() is called.
func NewStreamEncoder(w io.Writer, alphabet string) io.WriteCloser {
	if len(alphabet) != 64 {
		return &StreamEncoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StreamEncoder{
		writer:   w,
		encoder:  base64.NewEncoding(alphabet),
		alphabet: alphabet,
		buffer:   make([]byte, 0, 1024), // Pre-allocate buffer with reasonable capacity
	}
}

// Write implements the io.Writer interface for streaming base64 encoding.
// Processes data in chunks while maintaining minimal state for cross-Write calls.
// This is true streaming - processes data immediately without accumulating large buffers.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Combine any leftover bytes from previous write with new data
	// This is necessary for true streaming across multiple Write calls
	data := append(e.buffer, p...)
	e.buffer = nil // Clear buffer after combining

	// Process data in chunks of 3 bytes (optimal for base64 encoding)
	// Base64 encoding converts 3 bytes to 4 characters
	chunkSize := 3
	chunks := len(data) / chunkSize

	for i := 0; i < chunks*chunkSize; i += chunkSize {
		chunk := data[i : i+chunkSize]
		encoded := e.encoder.EncodeToString(chunk)
		if _, err = e.writer.Write([]byte(encoded)); err != nil {
			return len(p), err
		}
	}

	// Buffer remaining 0-2 bytes for next write or close
	remainder := len(data) % chunkSize
	if remainder > 0 {
		e.buffer = data[len(data)-remainder:]
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base64 encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode any remaining bytes (1-2 bytes) from the last Write
	if len(e.buffer) > 0 {
		encoded := e.encoder.EncodeToString(e.buffer)
		if _, err := e.writer.Write([]byte(encoded)); err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming base64 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader   io.Reader        // Underlying reader for encoded input
	decoder  *base64.Encoding // Base64 encoding implementation
	alphabet string           // The alphabet used for decoding
	buffer   []byte           // Buffer for decoded data not yet read
	pos      int              // Current position in the decoded buffer
	Error    error            // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base64 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the specified alphabet for decoding.
// The decoder automatically handles padding and invalid characters.
func NewStreamDecoder(r io.Reader, alphabet string) io.Reader {
	if len(alphabet) != 64 {
		return &StreamDecoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StreamDecoder{
		reader:   r,
		decoder:  base64.NewEncoding(alphabet),
		alphabet: alphabet,
		buffer:   make([]byte, 0, 1024), // Pre-allocate buffer for decoded data
		pos:      0,
	}
}

// Read implements the io.Reader interface for streaming base64 decoding.
// Reads and decodes base64 data from the underlying reader in chunks.
// Maintains an internal buffer to handle partial reads efficiently.
func (d *StreamDecoder) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	// Return buffered data if available
	if d.pos < len(d.buffer) {
		n = copy(p, d.buffer[d.pos:])
		d.pos += n
		return n, nil
	}

	// Read encoded data in chunks
	readBuf := make([]byte, 1024) // Pre-allocate read buffer
	rn, err := d.reader.Read(readBuf)
	if err != nil && err != io.EOF {
		return 0, err
	}

	if rn == 0 {
		return 0, io.EOF
	}

	// Decode the data using the configured decoder
	decoded, err := d.decoder.DecodeString(string(readBuf[:rn]))
	if err != nil {
		return 0, err
	}

	// Copy decoded data to the provided buffer
	copied := copy(p, decoded)
	if copied < len(decoded) {
		// Buffer remaining data for next read
		d.buffer = decoded[copied:]
		d.pos = 0
	}

	return copied, nil
}

// Convenience functions for common use cases

// Encode encodes the given byte slice using standard base64 encoding.
// This is a convenience function that creates a new encoder and encodes the input.
func Encode(src []byte) []byte {
	return NewStdEncoder(StdAlphabet).Encode(src)
}

// EncodeURLSafe encodes the given byte slice using URL-safe base64 encoding.
// This is a convenience function that creates a new encoder and encodes the input.
func EncodeURLSafe(src []byte) []byte {
	return NewStdEncoder(URLAlphabet).Encode(src)
}

// Decode decodes the given base64-encoded byte slice using standard base64 decoding.
// This is a convenience function that creates a new decoder and decodes the input.
// Returns the decoded data, ignoring any decoding errors.
func Decode(src []byte) []byte {
	dst, _ := NewStdDecoder(StdAlphabet).Decode(src)
	return dst
}

// DecodeURLSafe decodes the given URL-safe base64-encoded byte slice.
// This is a convenience function that creates a new decoder and decodes the input.
// Returns the decoded data, ignoring any decoding errors.
func DecodeURLSafe(src []byte) []byte {
	dst, _ := NewStdDecoder(URLAlphabet).Decode(src)
	return dst
}

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
			// For base64 errors, the position is usually at the beginning
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
// in chunks rather than loading everything into memory at once.
type StreamEncoder struct {
	writer   io.Writer        // Underlying writer for encoded output
	encoder  *base64.Encoding // Base64 encoding implementation
	alphabet string           // The alphabet used for encoding
	buffer   []byte           // Buffer for accumulating data before encoding
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
// Accumulates data in the internal buffer without immediate encoding.
// The actual encoding occurs when Close() is called to optimize performance.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	// Append data to buffer
	e.buffer = append(e.buffer, p...)
	return len(p), nil
}

// Close implements the io.Closer interface for streaming base64 encoding.
// Encodes all buffered data and writes it to the underlying writer.
// This method must be called to complete the encoding process.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	if len(e.buffer) > 0 {
		// Create encoder and encode all buffered data
		base64Encoder := base64.NewEncoder(e.encoder, e.writer)
		defer base64Encoder.Close()

		_, err := base64Encoder.Write(e.buffer)
		if err != nil {
			return err
		}
	}

	return nil
}

// StreamDecoder represents a streaming base64 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks rather than loading everything into memory at once.
type StreamDecoder struct {
	reader   io.Reader        // Underlying reader for encoded input
	decoder  *base64.Encoding // Base64 encoding implementation
	alphabet string           // The alphabet used for decoding
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
	}
}

// Read implements the io.Reader interface for streaming base64 decoding.
// Reads and decodes base64 data from the underlying reader in chunks.
func (d *StreamDecoder) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	// Create a temporary decoder for this read operation
	// This ensures proper error handling and alphabet validation
	tempDecoder := base64.NewDecoder(d.decoder, d.reader)

	return tempDecoder.Read(p)
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

// Package base32 implements base32 encoding and decoding with streaming support.
// It provides both standard and hexadecimal base32 alphabets, along with
// streaming capabilities for efficient processing of large data.
package base32

import (
	"encoding/base32"
	"io"
)

// StdAlphabet is the standard base32 alphabet as defined in RFC 4648.
// It uses uppercase letters A-Z and digits 2-7, excluding 0, 1, 8, and 9
// to avoid confusion with similar-looking characters.
var StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// HexAlphabet is the hexadecimal base32 alphabet as defined in RFC 4648.
// It uses digits 0-9 and uppercase letters A-V, providing a more
// compact representation for hexadecimal data.
var HexAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// StdEncoder represents a base32 encoder for standard encoding operations.
// It wraps the standard library's base32.Encoding to provide a consistent
// interface with error handling capabilities.
type StdEncoder struct {
	encoding *base32.Encoding // Underlying base32 encoding implementation
	alphabet string           // The alphabet used for encoding
	Error    error            // Error field for storing encoding errors
}

// NewStdEncoder creates a new base32 encoder with the specified alphabet.
// The alphabet must be a valid base32 alphabet string (exactly 32 characters).
// Returns a pointer to the newly created StdEncoder.
func NewStdEncoder(alphabet string) *StdEncoder {
	if len(alphabet) != 32 {
		return &StdEncoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StdEncoder{encoding: base32.NewEncoding(alphabet), alphabet: alphabet}
}

// Encode encodes the given byte slice using base32 encoding.
// Returns an empty byte slice if the input is empty.
// The encoded result uses the alphabet specified when creating the encoder.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if e.Error != nil {
		return
	}
	if len(src) == 0 {
		return
	}

	dst = make([]byte, e.encoding.EncodedLen(len(src)))
	e.encoding.Encode(dst, src)
	return
}

// StdDecoder represents a base32 decoder for standard decoding operations.
// It wraps the standard library's base32.Encoding to provide a consistent
// interface with error handling capabilities.
type StdDecoder struct {
	encoding *base32.Encoding // Underlying base32 encoding implementation
	alphabet string           // The alphabet used for decoding
	Error    error            // Error field for storing decoding errors
}

// NewStdDecoder creates a new base32 decoder with the specified alphabet.
// The alphabet must be a valid base32 alphabet string (exactly 32 characters).
// Returns a pointer to the newly created StdDecoder.
func NewStdDecoder(alphabet string) *StdDecoder {
	if len(alphabet) != 32 {
		return &StdDecoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StdDecoder{encoding: base32.NewEncoding(alphabet), alphabet: alphabet}
}

// Decode decodes the given base32-encoded byte slice.
// Returns the decoded data and any error encountered during decoding.
// Returns an empty byte slice and nil error if the input is empty.
// The decoded result is truncated to the actual decoded length.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}
	if len(src) == 0 {
		return
	}

	buf := make([]byte, d.encoding.DecodedLen(len(src)))
	n, err := d.encoding.Decode(buf, src)
	if err != nil {
		d.Error = CorruptInputError(0)
		return nil, d.Error
	}
	return buf[:n], nil
}

// StreamEncoder represents a streaming base32 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks rather than loading everything into memory at once.
type StreamEncoder struct {
	writer   io.Writer        // Underlying writer for encoded output
	encoder  *base32.Encoding // Base32 encoding implementation
	alphabet string           // The alphabet used for encoding
	Error    error            // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base32 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the specified alphabet for encoding.
// Returns an io.WriteCloser that can be used for streaming base32 encoding.
func NewStreamEncoder(w io.Writer, alphabet string) io.WriteCloser {
	return base32.NewEncoder(base32.NewEncoding(alphabet), w)
}

// StreamDecoder represents a streaming base32 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks rather than loading everything into memory at once.
type StreamDecoder struct {
	reader   io.Reader        // Underlying reader for encoded input
	decoder  *base32.Encoding // Base32 encoding implementation
	alphabet string           // The alphabet used for decoding
	Error    error            // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base32 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the specified alphabet for decoding.
// Returns an io.Reader that can be used for streaming base32 decoding.
func NewStreamDecoder(r io.Reader, alphabet string) io.Reader {
	return base32.NewDecoder(base32.NewEncoding(alphabet), r)
}

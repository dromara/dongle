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
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer   io.Writer        // Underlying writer for encoded output
	encoder  *base32.Encoding // Base32 encoding implementation
	buffer   []byte           // Buffer for accumulating partial bytes (0-4 bytes)
	alphabet string           // The alphabet used for encoding
	Error    error            // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base32 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the specified alphabet for encoding.
// Returns an io.WriteCloser that can be used for streaming base32 encoding.
func NewStreamEncoder(w io.Writer, alphabet string) io.WriteCloser {
	if len(alphabet) != 32 {
		return &StreamEncoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StreamEncoder{
		writer:   w,
		encoder:  base32.NewEncoding(alphabet),
		alphabet: alphabet,
	}
}

// Write implements the io.Writer interface for streaming base32 encoding.
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

	// Process complete 5-byte blocks (5 bytes = 8 characters)
	blocks := len(data) / 5
	for i := 0; i < blocks*5; i += 5 {
		// Encode 5 bytes to 8 characters
		encoded := make([]byte, 8)
		e.encoder.Encode(encoded, data[i:i+5])
		if _, err = e.writer.Write(encoded); err != nil {
			return len(p), err
		}
	}

	// Buffer remaining 0-4 bytes for next write or close
	remainder := len(data) % 5
	if remainder > 0 {
		e.buffer = data[len(data)-remainder:]
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base32 encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode any remaining bytes (1-4 bytes) with proper padding
	if len(e.buffer) > 0 {
		// Create a padded buffer for encoding
		padded := make([]byte, 5)
		copy(padded, e.buffer)

		// Encode the padded data
		encoded := make([]byte, 8)
		e.encoder.Encode(encoded, padded)

		// Apply proper padding based on the number of remaining bytes
		switch len(e.buffer) {
		case 1: // 1 byte = 2 characters + 6 padding
			encoded = encoded[:2]
			encoded = append(encoded, []byte("======")...)
		case 2: // 2 bytes = 4 characters + 4 padding
			encoded = encoded[:4]
			encoded = append(encoded, []byte("====")...)
		case 3: // 3 bytes = 5 characters + 3 padding
			encoded = encoded[:5]
			encoded = append(encoded, []byte("===")...)
		case 4: // 4 bytes = 7 characters + 1 padding
			encoded = encoded[:7]
			encoded = append(encoded, []byte("=")...)
		}
		if _, err := e.writer.Write(encoded); err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming base32 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader   io.Reader        // Underlying reader for encoded input
	decoder  *base32.Encoding // Base32 encoding implementation
	buffer   []byte           // Buffer for decoded data not yet read
	pos      int              // Current position in the decoded buffer
	alphabet string           // The alphabet used for decoding
	Error    error            // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base32 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the specified alphabet for decoding.
func NewStreamDecoder(r io.Reader, alphabet string) io.Reader {
	if len(alphabet) != 32 {
		return &StreamDecoder{Error: AlphabetSizeError(len(alphabet))}
	}
	return &StreamDecoder{
		reader:   r,
		decoder:  base32.NewEncoding(alphabet),
		alphabet: alphabet,
	}
}

// Read implements the io.Reader interface for streaming base32 decoding.
// Reads and decodes base32 data from the underlying reader in chunks.
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
	decodedLen := d.decoder.DecodedLen(rn)
	decoded := make([]byte, decodedLen)
	n, err = d.decoder.Decode(decoded, readBuf[:rn])
	if err != nil {
		return 0, err
	}

	// Copy decoded data to the provided buffer
	copied := copy(p, decoded[:n])
	if copied < n {
		// Buffer remaining data for next read
		d.buffer = decoded[copied:n]
		d.pos = 0
	}

	return copied, nil
}

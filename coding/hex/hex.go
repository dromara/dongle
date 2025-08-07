// Package hex implements hex encoding and decoding with streaming support.
// It provides hexadecimal encoding using the standard 16-character alphabet
// (0-9, A-F) for efficient binary-to-text encoding and decoding.
package hex

import (
	"encoding/hex"
	"io"
)

// StdEncoder represents a hex encoder for standard encoding operations.
// It wraps the standard library's hex encoding to provide a consistent
// interface with error handling capabilities.
type StdEncoder struct {
	Error error // Error field for storing encoding errors
}

// NewStdEncoder creates a new hex encoder using the standard hex alphabet.
func NewStdEncoder() *StdEncoder {
	return &StdEncoder{}
}

// Encode encodes the given byte slice using hex encoding.
// Returns an empty byte slice if the input is empty.
// The encoding process uses the standard hex alphabet (0-9, A-F).
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if len(src) == 0 {
		return
	}

	dst = make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return
}

// StdDecoder represents a hex decoder for standard decoding operations.
// It wraps the standard library's hex decoding to provide a consistent
// interface with error handling capabilities.
type StdDecoder struct {
	Error error // Error field for storing decoding errors
}

// NewStdDecoder creates a new hex decoder using the standard hex alphabet.
func NewStdDecoder() *StdDecoder {
	return &StdDecoder{}
}

// Decode decodes the given hex-encoded byte slice back to binary data.
// Returns the decoded data and any error encountered during decoding.
// Returns an empty byte slice and nil error if the input is empty.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}

	buf := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(buf, src)
	if err != nil {
		return
	}
	return buf[:n], nil
}

// StreamEncoder represents a streaming hex encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks rather than loading everything into memory at once.
type StreamEncoder struct {
	writer  io.Writer // Underlying writer for encoded output
	encoder io.Writer // Hex encoding implementation
	Error   error     // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming hex encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard hex alphabet.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	encoder := hex.NewEncoder(w)
	return &StreamEncoder{
		writer:  w,
		encoder: encoder,
	}
}

// Write implements the io.Writer interface for streaming hex encoding.
// Writes data to the underlying hex encoder for immediate encoding.
// Returns the number of bytes written and any error encountered.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	return e.encoder.Write(p)
}

// Close implements the io.Closer interface for streaming hex encoding.
// Hex encoding is immediate, so Close() performs no additional operations.
func (e *StreamEncoder) Close() error {
	return nil
}

// StreamDecoder represents a streaming hex decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks rather than loading everything into memory at once.
type StreamDecoder struct {
	reader  io.Reader // Underlying reader for encoded input
	decoder io.Reader // Hex decoding implementation
	Error   error     // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming hex decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard hex alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	decoder := hex.NewDecoder(r)
	return &StreamDecoder{
		reader:  r,
		decoder: decoder,
	}
}

// Read implements the io.Reader interface for streaming hex decoding.
// Reads and decodes hex data from the underlying decoder in chunks.
// Returns the number of bytes read and any error encountered.
func (d *StreamDecoder) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}
	return d.decoder.Read(p)
}

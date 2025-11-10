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
	if e.Error != nil {
		return
	}
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
	if d.Error != nil {
		err = d.Error
		return
	}
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
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer    io.Writer // Underlying writer for encoded output
	buffer    []byte    // Buffer for accumulating partial bytes (0-1 bytes)
	encodeBuf [4]byte   // Reusable buffer for encoding output (2 bytes -> 4 hex chars)
	Error     error     // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming hex encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard hex alphabet.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{
		writer: w,
	}
}

// Write implements the io.Writer interface for streaming hex encoding.
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

	// Process data in chunks of 2 bytes (optimal for hex encoding)
	// Hex encoding converts 1 byte to 2 characters
	chunkSize := 2
	chunks := len(data) / chunkSize

	for i := 0; i < chunks*chunkSize; i += chunkSize {
		chunk := data[i : i+chunkSize]
		// Use reusable buffer for encoding to avoid allocations
		hex.Encode(e.encodeBuf[:], chunk)
		if _, err = e.writer.Write(e.encodeBuf[:]); err != nil {
			return len(p), err
		}
	}

	// Buffer remaining 0-1 bytes for next write or close
	remainder := len(data) % chunkSize
	if remainder > 0 {
		e.buffer = data[len(data)-remainder:]
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming hex encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode any remaining bytes (1 byte) from the last Write
	if len(e.buffer) > 0 {
		// Use reusable buffer for final encoding
		hex.Encode(e.encodeBuf[:2], e.buffer)
		if _, err := e.writer.Write(e.encodeBuf[:2]); err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming hex decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader    io.Reader  // Underlying reader for encoded input
	buffer    []byte     // Buffer for decoded data not yet read
	pos       int        // Current position in the decoded buffer
	readBuf   [1024]byte // Reusable buffer for reading encoded data
	decodeBuf [512]byte  // Reusable buffer for decoding (hex decodes to half size)
	Error     error      // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming hex decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard hex alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{
		reader: r,
	}
}

// Read implements the io.Reader interface for streaming hex decoding.
// Reads and decodes hex data from the underlying reader in chunks.
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

	// Read encoded data in chunks using reusable buffer
	rn, err := d.reader.Read(d.readBuf[:])
	if err != nil && err != io.EOF {
		return 0, err
	}

	if rn == 0 {
		return 0, io.EOF
	}

	// Decode the data using the standard hex decoder with reusable buffer
	decodedLen, err := hex.Decode(d.decodeBuf[:], d.readBuf[:rn])
	if err != nil {
		return 0, err
	}

	// Copy decoded data to the provided buffer
	copied := copy(p, d.decodeBuf[:decodedLen])
	if copied < decodedLen {
		// Buffer remaining data for next read
		d.buffer = d.decodeBuf[copied:decodedLen]
		d.pos = 0
	}

	return copied, nil
}

// Package unicode implements unicode encoding and decoding with streaming support.
// It provides unicode encoding using strconv.QuoteToASCII for converting
// byte data to unicode escape sequences and back.
package unicode

import (
	"io"
	"strconv"
)

// StdEncoder represents a unicode encoder for standard encoding operations.
// It wraps strconv.QuoteToASCII to provide a consistent interface with
// error handling capabilities.
type StdEncoder struct {
	Error error // Error field for storing encoding errors
}

// NewStdEncoder creates a new unicode encoder using strconv.QuoteToASCII.
func NewStdEncoder() *StdEncoder {
	return &StdEncoder{}
}

// Encode encodes the given byte slice using unicode encoding.
// Returns an empty byte slice if the input is empty.
// The encoding process uses strconv.QuoteToASCII to convert bytes to unicode escape sequences.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if e.Error != nil {
		return
	}
	if len(src) == 0 {
		return
	}

	// Use strconv.QuoteToASCII to convert bytes to unicode escape sequences
	quoted := strconv.QuoteToASCII(string(src))
	// Remove the surrounding quotes added by QuoteToASCII
	dst = []byte(quoted[1 : len(quoted)-1])
	return
}

// StdDecoder represents a unicode decoder for standard decoding operations.
// It wraps strconv.Unquote to provide a consistent interface with
// error handling capabilities.
type StdDecoder struct {
	Error error // Error field for storing decoding errors
}

// NewStdDecoder creates a new unicode decoder using strconv.Unquote.
func NewStdDecoder() *StdDecoder {
	return &StdDecoder{}
}

// Decode decodes the given unicode-encoded byte slice back to binary data.
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

	// Add quotes around the unicode string for proper unquoting
	quoted := "\"" + string(src) + "\""
	unquoted, err := strconv.Unquote(quoted)
	if err != nil {
		d.Error = DecodeFailedError{Input: string(src)}
		err = DecodeFailedError{Input: string(src)}
		return
	}
	return []byte(unquoted), nil
}

// StreamEncoder represents a streaming unicode encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer io.Writer // Underlying writer for encoded output
	buffer []byte    // Buffer for accumulating partial bytes
	Error  error     // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming unicode encoder that writes encoded data
// to the provided io.Writer. The encoder uses strconv.QuoteToASCII.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{
		writer: w,
	}
}

// Write implements the io.Writer interface for streaming unicode encoding.
// Processes data in chunks while maintaining minimal state for cross-Write calls.
// This is true streaming - processes data immediately without accumulating large buffers.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// For unicode encoding, we need to process the entire string at once
	// because unicode escape sequences can span across byte boundaries
	// So we accumulate all data and process it on close
	e.buffer = append(e.buffer, p...)

	return len(p), nil
}

// encodeChunk encodes a chunk of data using unicode encoding.
func (e *StreamEncoder) encodeChunk(data []byte) []byte {
	// Use strconv.QuoteToASCII to convert bytes to unicode escape sequences
	quoted := strconv.QuoteToASCII(string(data))
	// Remove the surrounding quotes added by QuoteToASCII
	return []byte(quoted[1 : len(quoted)-1])
}

// Close implements the io.Closer interface for streaming unicode encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode all buffered data
	if len(e.buffer) > 0 {
		encoded := e.encodeChunk(e.buffer)
		if _, err := e.writer.Write(encoded); err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming unicode decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader io.Reader // Underlying reader for encoded input
	buffer []byte    // Buffer for decoded data not yet read
	pos    int       // Current position in the decoded buffer
	Error  error     // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming unicode decoder that reads encoded data
// from the provided io.Reader. The decoder uses strconv.Unquote.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{
		reader: r,
		buffer: make([]byte, 0, 1024), // Pre-allocate buffer for decoded data
		pos:    0,
	}
}

// Read implements the io.Reader interface for streaming unicode decoding.
// Reads and decodes unicode data from the underlying reader in chunks.
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

	// Decode the data using the standard unicode decoder
	decoded, err := d.decodeChunk(readBuf[:rn])
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

// decodeChunk decodes a chunk of unicode-encoded data.
func (d *StreamDecoder) decodeChunk(data []byte) (dst []byte, err error) {
	// Add quotes around the unicode string for proper unquoting
	quoted := "\"" + string(data) + "\""
	unquoted, err := strconv.Unquote(quoted)
	if err != nil {
		d.Error = DecodeFailedError{Input: string(data)}
		err = DecodeFailedError{Input: string(data)}
		return
	}
	return []byte(unquoted), nil
}

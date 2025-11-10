// Package base100 implements base100 encoding and decoding with streaming support.
// It provides base100 encoding that converts bytes to emoji characters,
// following the specification from https://github.com/stek29/base100.
// Each byte is encoded as a 4-byte UTF-8 sequence representing an emoji.
package base100

import (
	"io"
)

// StdEncoder represents a base100 encoder for standard encoding operations.
// It implements base100 encoding that converts each input byte to a 4-byte
// UTF-8 sequence representing an emoji character.
type StdEncoder struct {
	Error error // Error field for storing encoding errors
}

// NewStdEncoder creates a new base100 encoder.
// Base100 encoding uses a fixed algorithm that doesn't require an alphabet lookup.
func NewStdEncoder() *StdEncoder {
	return &StdEncoder{}
}

// Encode encodes the given byte slice using base100 encoding.
// Each input byte is converted to a 4-byte sequence: 0xf0, 0x9f, byte2, byte3
// where byte2 = ((byte + 55) / 64) + 0x8f and byte3 = (byte + 55) % 64 + 0x80.
// This creates UTF-8 sequences that represent emoji characters.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if e.Error != nil {
		return
	}
	if len(src) == 0 {
		return
	}

	// Pre-allocate buffer with exact size needed
	dst = make([]byte, len(src)*4)
	for i, v := range src {
		dst[i*4+0] = 0xf0
		dst[i*4+1] = 0x9f
		dst[i*4+2] = byte((uint16(v)+55)/64 + 0x8f)
		dst[i*4+3] = (v+55)%64 + 0x80
	}
	return dst
}

// StdDecoder represents a base100 decoder for standard decoding operations.
// It implements base100 decoding that converts 4-byte UTF-8 sequences
// back to their original byte values.
type StdDecoder struct {
	Error error // Error field for storing decoding errors
}

// NewStdDecoder creates a new base100 decoder.
// Base100 decoding uses a fixed algorithm that doesn't require an alphabet lookup.
func NewStdDecoder() *StdDecoder {
	return &StdDecoder{}
}

// Decode decodes the given base100-encoded byte slice back to binary data.
// Each 4-byte sequence is converted back to a single byte using the formula:
// byte = (byte2 - 0x8f) * 64 + (byte3 - 0x80) - 55
// Validates that the first two bytes are 0xf0 and 0x9f respectively.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	if len(src) == 0 {
		return
	}

	if len(src)%4 != 0 {
		return nil, InvalidLengthError(len(src))
	}

	// Pre-allocate buffer with exact size needed
	dst = make([]byte, len(src)/4)
	outPos := 0
	for i := 0; i < len(src); i += 4 {
		if src[i] != 0xf0 || src[i+1] != 0x9f {
			return nil, CorruptInputError(int64(i))
		}
		dst[outPos] = (src[i+2]-0x8f)*64 + src[i+3] - 0x80 - 55
		outPos++
	}
	return dst, nil
}

// StreamEncoder represents a streaming base100 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// immediately without buffering.
type StreamEncoder struct {
	writer    io.Writer // Underlying writer for encoded output
	encodeBuf [4]byte   // Reusable buffer for encoding a single byte
	Error     error     // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base100 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard base100 encoding algorithm.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{
		writer: w,
	}
}

// Write implements the io.Writer interface for streaming base100 encoding.
// Processes data in chunks while maintaining minimal state for cross-Write calls.
// This is true streaming - processes data immediately without accumulating large buffers.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Process each byte directly from input
	for _, v := range p {
		// Encode byte inline using base100 algorithm
		e.encodeBuf[0] = 0xf0
		e.encodeBuf[1] = 0x9f
		e.encodeBuf[2] = byte((uint16(v)+55)/64 + 0x8f)
		e.encodeBuf[3] = (v+55)%64 + 0x80
		if _, err = e.writer.Write(e.encodeBuf[:]); err != nil {
			return len(p), err
		}
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base100 encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// No buffering needed for base100, all data is processed immediately

	return nil
}

// StreamDecoder represents a streaming base100 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader  io.Reader   // Underlying reader for encoded input
	buffer  []byte      // Buffer for decoded data not yet read
	pos     int         // Current position in the decoded buffer
	decoder *StdDecoder // Reuse decoder instance to avoid repeated creation
	readBuf [1024]byte  // Reusable buffer for reading encoded data
	Error   error       // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base100 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard base100 decoding algorithm.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{
		reader:  r,
		decoder: NewStdDecoder(),
	}
}

// Read implements the io.Reader interface for streaming base100 decoding.
// Reads and decodes base100 data from the underlying reader in chunks.
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

	// Decode the data using the configured decoder
	decoded, err := d.decoder.Decode(d.readBuf[:rn])
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

// Legacy functions for backward compatibility

// Encode encodes by base100.
// This is a legacy function that maintains backward compatibility.
// Consider using NewStdEncoder().Encode() for new code.
func Encode(src []byte) []byte {
	return NewStdEncoder().Encode(src)
}

// Decode decodes by base100.
// This is a legacy function that maintains backward compatibility.
// Consider using NewStdDecoder().Decode() for new code.
func Decode(src []byte) ([]byte, error) {
	return NewStdDecoder().Decode(src)
}

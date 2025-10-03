// Package base91 implements base91 encoding and decoding with streaming support.
// It provides base91 encoding following the specification at http://base91.sourceforge.net,
// using a 91-character alphabet that excludes space, apostrophe, hyphen, and backslash
// from the 95 printable ASCII characters for maximum character efficiency.
package base91

import (
	"io"
	"math"
)

// StdAlphabet is the standard base91 alphabet used for encoding and decoding.
// It includes uppercase letters A-Z, lowercase letters a-z, digits 0-9, and special
// characters for a total of 91 characters, excluding space, apostrophe, hyphen, and backslash.
var StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""

// StdEncoder represents a base91 encoder for standard encoding operations.
// It implements base91 encoding following the specification at http://base91.sourceforge.net,
// providing efficient encoding of binary data to base91 strings with optimal bit packing.
type StdEncoder struct {
	encodeMap [91]byte // Lookup table for fast encoding of values to characters
	alphabet  string   // The alphabet used for encoding
	Error     error    // Error field for storing encoding errors
}

// NewStdEncoder creates a new base91 encoder using the standard alphabet.
// Initializes the encoding lookup table for efficient character mapping.
func NewStdEncoder() *StdEncoder {
	e := &StdEncoder{alphabet: StdAlphabet}
	alphabet := StdAlphabet
	copy(e.encodeMap[:], alphabet)
	return e
}

// Encode encodes the given byte slice using base91 encoding.
// Uses a bit-packing algorithm that groups 13 or 14 bits into 16-bit values
// for optimal encoding efficiency, following the base91 specification.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if len(src) == 0 {
		return
	}

	// Calculate the maximum output size for pre-allocation
	maxLen := e.EncodedLen(len(src))
	dst = make([]byte, maxLen)

	actualLen := e.encode(dst, src)
	return dst[:actualLen]
}

// encode performs the actual base91 encoding using bit-packing algorithm.
// Groups input bytes into 13 or 14-bit chunks and encodes them as 16-bit values.
func (e *StdEncoder) encode(dst, src []byte) int {
	var queue, numBits uint

	n := 0
	for i := 0; i < len(src); i++ {
		queue |= uint(src[i]) << numBits
		numBits += 8
		if numBits > 13 {
			var v = queue & 8191

			if v > 88 {
				queue >>= 13
				numBits -= 13
			} else {
				// We can take 14 bits.
				v = queue & 16383
				queue >>= 14
				numBits -= 14
			}
			dst[n] = e.encodeMap[v%91]
			n++
			dst[n] = e.encodeMap[v/91]
			n++
		}
	}

	if numBits > 0 {
		dst[n] = e.encodeMap[queue%91]
		n++

		if numBits > 7 || queue > 90 {
			dst[n] = e.encodeMap[queue/91]
			n++
		}
	}

	return n
}

// EncodedLen returns an upper bound on the length in bytes of the base91 encoding
// of an input buffer of length n. The true encoded length may be shorter.
func (e *StdEncoder) EncodedLen(n int) int {
	// At worst, base91 encodes 13 bits into 16 bits. Even though 14 bits can
	// sometimes be encoded into 16 bits, assume the worst case to get the upper
	// bound on encoded length.
	return int(math.Ceil(float64(n) * 16.0 / 13.0))
}

// StdDecoder represents a base91 decoder for standard decoding operations.
// It implements base91 decoding following the specification at http://base91.sourceforge.net,
// providing efficient decoding of base91 strings back to binary data with proper
// bit unpacking and validation.
type StdDecoder struct {
	decodeMap [256]byte // Lookup table for fast decoding of characters to values
	alphabet  string    // The alphabet used for decoding
	Error     error     // Error field for storing decoding errors
}

// NewStdDecoder creates a new base91 decoder using the standard alphabet.
// Initializes the decoding lookup table for efficient character mapping.
// Invalid characters are marked with 0xFF for error detection.
func NewStdDecoder() *StdDecoder {
	d := &StdDecoder{alphabet: StdAlphabet}
	alphabet := StdAlphabet
	for i := 0; i < 256; i++ {
		d.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(alphabet); i++ {
		d.decodeMap[alphabet[i]] = byte(i)
	}
	return d
}

// Decode decodes the given base91-encoded byte slice back to binary data.
// Uses bit-unpacking algorithm to reconstruct the original binary data
// and validates character validity during decoding.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}

	// Calculate the maximum output size for pre-allocation
	maxLen := d.DecodedLen(len(src))
	dst = make([]byte, maxLen)

	actualLen, err := d.decode(dst, src)
	if err != nil {
		return nil, err
	}

	return dst[:actualLen], nil
}

// decode performs the actual base91 decoding using bit-unpacking algorithm.
// Reconstructs binary data from 16-bit encoded values by reversing the encoding process.
func (d *StdDecoder) decode(dst, src []byte) (int, error) {
	var queue, numBits uint
	var v = -1

	n := 0
	for i := 0; i < len(src); i++ {
		if d.decodeMap[src[i]] == 0xFF {
			// The character is not in the encoding alphabet.
			return n, CorruptInputError(int64(i))
		}

		if v == -1 {
			// Start the next value.
			v = int(d.decodeMap[src[i]])
		} else {
			v += int(d.decodeMap[src[i]]) * 91
			queue |= uint(v) << numBits

			if (v & 8191) > 88 {
				numBits += 13
			} else {
				numBits += 14
			}

			for ok := true; ok; ok = numBits > 7 {
				dst[n] = byte(queue)
				n++

				queue >>= 8
				numBits -= 8
			}

			// Mark this value complete.
			v = -1
		}
	}

	if v != -1 {
		dst[n] = byte(queue | uint(v)<<numBits)
		n++
	}

	return n, nil
}

// DecodedLen returns the maximum length in bytes of the decoded data
// corresponding to n bytes of base91-encoded data.
func (d *StdDecoder) DecodedLen(n int) int {
	// At best, base91 encodes 14 bits into 16 bits, so assume that the input is
	// optimally encoded to get the upper bound on decoded length.
	return int(math.Ceil(float64(n) * 14.0 / 16.0))
}

// StreamEncoder represents a streaming base91 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer   io.Writer // Underlying writer for encoded output
	buffer   []byte    // Buffer for accumulating partial bytes (0-12 bytes)
	alphabet string    // The alphabet used for encoding
	Error    error     // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base91 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard base91 alphabet.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{writer: w, alphabet: StdAlphabet}
}

// Write implements the io.Writer interface for streaming base91 encoding.
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

	// Process data in chunks of 13 bytes (optimal for base91 encoding)
	// Base91 encoding converts 13 bits to 16 bits (2 characters)
	chunkSize := 13
	chunks := len(data) / chunkSize

	for i := 0; i < chunks*chunkSize; i += chunkSize {
		chunk := data[i : i+chunkSize]
		enc := &StdEncoder{}
		copy(enc.encodeMap[:], e.alphabet)
		encoded := enc.Encode(chunk)
		if _, err = e.writer.Write(encoded); err != nil {
			return len(p), err
		}
	}

	// Buffer remaining 0-12 bytes for next write or close
	remainder := len(data) % chunkSize
	if remainder > 0 {
		e.buffer = data[len(data)-remainder:]
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base91 encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode any remaining bytes (1-12 bytes) from the last Write
	if len(e.buffer) > 0 {
		enc := &StdEncoder{}
		copy(enc.encodeMap[:], e.alphabet)
		encoded := enc.Encode(e.buffer)
		if _, err := e.writer.Write(encoded); err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming base91 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader   io.Reader   // Underlying reader for encoded input
	buffer   []byte      // Buffer for decoded data not yet read
	pos      int         // Current position in the decoded buffer
	decoder  *StdDecoder // Reuse decoder instance
	alphabet string      // The alphabet used for decoding
	Error    error       // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base91 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard base91 alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{
		reader:   r,
		decoder:  NewStdDecoder(),
		alphabet: StdAlphabet,
		buffer:   make([]byte, 0, 1024), // Pre-allocate buffer for decoded data
		pos:      0,
	}
}

// Read implements the io.Reader interface for streaming base91 decoding.
// Reads and decodes base91 data from the underlying reader in chunks.
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
	decoded, err := d.decoder.Decode(readBuf[:rn])
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

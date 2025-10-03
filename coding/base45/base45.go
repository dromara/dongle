// Package base45 implements base45 encoding and decoding with streaming support.
// It provides base45 encoding as defined in RFC 9285, which is designed for
// efficient encoding of binary data using a 45-character alphabet.
package base45

import (
	"io"
)

const (
	// baseRadix represents the base45 radix used in encoding/decoding calculations
	baseRadix = 45
	// baseSquare represents base45 squared (45^2) for efficient encoding of 2-byte sequences
	baseSquare = 45 * 45
	// maxUint16 represents the maximum value for uint16, used for validation
	maxUint16 = 0xFFFF
)

// StdAlphabet is the standard base45 alphabet as defined in RFC 9285.
// It includes digits 0-9, uppercase letters A-Z, and special characters
// space, $, %, *, +, -, ., /, and : for a total of 45 characters.
var StdAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

// StdEncoder represents a base45 encoder for standard encoding operations.
// It implements the base45 encoding algorithm as specified in RFC 9285,
// providing efficient encoding of binary data to base45 strings.
type StdEncoder struct {
	encodeMap [45]byte // Lookup table for fast encoding of values to characters
	alphabet  string   // The alphabet used for encoding
	Error     error    // Error field for storing encoding errors
}

// NewStdEncoder creates a new base45 encoder using the standard alphabet.
// Initializes the encoding lookup table for efficient character mapping.
func NewStdEncoder() *StdEncoder {
	e := &StdEncoder{alphabet: StdAlphabet}
	copy(e.encodeMap[:], StdAlphabet)
	return e
}

// Encode encodes the given byte slice using base45 encoding as per RFC 9285.
// Base45 encodes 2 bytes in 3 characters, or 1 byte in 2 characters.
// The encoding process handles both even and odd-length inputs efficiently.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	// Pre-calculate output size for better memory allocation
	outputSize := e.getOutputSize(len(src))
	if len(src) == 0 {
		return
	}

	result := make([]byte, 0, outputSize)

	for i := 0; i < len(src); i += 2 {
		if i+1 < len(src) {
			// Two bytes: encode as uint16 using base45^2
			n := uint16(src[i])<<8 | uint16(src[i+1])
			v, x := n/baseSquare, n%baseSquare
			d, c := x/baseRadix, x%baseRadix
			result = append(result, e.encodeMap[c], e.encodeMap[d], e.encodeMap[v])
		} else {
			// Single byte: encode as uint8 using base45
			n := uint16(src[i])
			d, c := n/baseRadix, n%baseRadix
			result = append(result, e.encodeMap[c], e.encodeMap[d])
		}
	}
	return result
}

// getOutputSize calculates the output size for a given input length
func (e *StdEncoder) getOutputSize(inputLen int) int {
	if inputLen == 0 {
		return 0
	}
	// Each pair of bytes produces 3 characters, each single byte produces 2 characters
	pairs := inputLen / 2
	singles := inputLen % 2
	return pairs*3 + singles*2
}

// StdDecoder represents a base45 decoder for standard decoding operations.
// It implements the base45 decoding algorithm as specified in RFC 9285,
// providing efficient decoding of base45 strings back to binary data.
type StdDecoder struct {
	decodeMap [256]byte // Lookup table for fast decoding of characters to values
	alphabet  string    // The alphabet used for decoding
	Error     error     // Error field for storing decoding errors
}

// NewStdDecoder creates a new base45 decoder using the standard alphabet.
// Initializes the decoding lookup table for efficient character mapping.
func NewStdDecoder() *StdDecoder {
	d := &StdDecoder{alphabet: StdAlphabet}
	// Initialize all values to invalid (0xFF)
	for i := range d.decodeMap {
		d.decodeMap[i] = 0xFF
	}
	// Set valid values for the alphabet
	for i, char := range StdAlphabet {
		d.decodeMap[byte(char)] = byte(i)
	}
	return d
}

// Decode decodes the given base45-encoded byte slice back to binary data.
// Validates input length (must be congruent to 0 or 2 modulo 3) and character validity.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	size := len(src)
	// Pre-allocate with estimated capacity
	estimatedSize := d.getDecodedSize(size)
	if size == 0 {
		return
	}
	mod := size % 3
	if mod != 0 && mod != 2 {
		err = InvalidLengthError{Length: size, Mod: mod}
		return
	}

	bytes := make([]byte, 0, size)

	for pos, char := range src {
		v := d.decodeMap[char]
		if v == 0xFF {
			err = InvalidCharacterError{Char: rune(char), Position: pos}
			return
		}
		bytes = append(bytes, v)
	}

	decoded := make([]byte, 0, estimatedSize)
	for i := 0; i < len(bytes); i += 3 {
		if i+2 < len(bytes) {
			// Three characters: decode to 2 bytes
			c, v, e := int(bytes[i]), int(bytes[i+1]), int(bytes[i+2])
			n := c + v*baseRadix + e*baseSquare
			if n > maxUint16 {
				err = CorruptInputError(int64(i / 3))
				return
			}
			decoded = append(decoded, byte(n>>8), byte(n&0xFF))
		} else if i+1 < len(bytes) {
			// Two characters: decode to 1 byte
			c, v := int(bytes[i]), int(bytes[i+1])
			n := c + v*baseRadix
			if n > 255 {
				err = CorruptInputError(int64(i / 3))
				return
			}
			decoded = append(decoded, byte(n))
		}
	}
	return decoded, nil
}

// getDecodedSize calculates the decoded size for a given encoded length
func (d *StdDecoder) getDecodedSize(encodedLen int) int {
	if encodedLen == 0 {
		return 0
	}
	// Each group of 3 characters produces 2 bytes, each group of 2 characters produces 1 byte
	groups := encodedLen / 3
	remainder := encodedLen % 3
	return groups*2 + remainder/2
}

// StreamEncoder represents a streaming base45 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer   io.Writer // Underlying writer for encoded output
	buffer   []byte    // Buffer for accumulating partial bytes (0-1 bytes)
	alphabet string    // The alphabet used for encoding
	Error    error     // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base45 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard base45 alphabet.
// Returns an io.WriteCloser that can be used for streaming base45 encoding.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{writer: w, alphabet: StdAlphabet}
}

// Write implements the io.Writer interface for streaming base45 encoding.
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

	// Process complete pairs (2 bytes = 3 characters)
	pairs := len(data) / 2
	for i := 0; i < pairs*2; i += 2 {
		// Encode 2 bytes to 3 characters
		val := uint16(data[i])<<8 | uint16(data[i+1])
		v, x := val/baseSquare, val%baseSquare
		d, c := x/baseRadix, x%baseRadix

		encoded := []byte{StdAlphabet[c], StdAlphabet[d], StdAlphabet[v]}
		if _, err = e.writer.Write(encoded); err != nil {
			return len(p), err
		}
	}

	// Buffer remaining 0-1 bytes for next write or close
	remainder := len(data) % 2
	if remainder > 0 {
		e.buffer = data[len(data)-remainder:]
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base45 encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode any remaining single byte from the last Write
	if len(e.buffer) == 1 {
		val := uint16(e.buffer[0])
		d, c := val/baseRadix, val%baseRadix
		encoded := []byte{StdAlphabet[c], StdAlphabet[d]}
		if _, err := e.writer.Write(encoded); err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming base45 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader   io.Reader // Underlying reader for encoded input
	buffer   []byte    // Buffer for decoded data not yet read
	pos      int       // Current position in the decoded buffer
	alphabet string    // The alphabet used for decoding
	Error    error     // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base45 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard base45 alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{reader: r, alphabet: StdAlphabet}
}

// Read implements the io.Reader interface for streaming base45 decoding.
// Reads and decodes base45 data from the underlying reader in chunks.
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
	decoder := NewStdDecoder()
	decoded, err := decoder.Decode(readBuf[:rn])
	if err != nil {
		return 0, err
	}

	// Copy decoded data to the provided buffer
	n = copy(p, decoded)
	if n < len(decoded) {
		// Buffer remaining data for next read
		d.buffer = decoded[n:]
		d.pos = 0
	}

	return n, nil
}

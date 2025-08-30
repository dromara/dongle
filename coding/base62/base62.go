// Package base62 implements base62 encoding and decoding with streaming support.
// It provides base62 encoding strictly following Python base62 library specifications,
// using a 62-character alphabet including digits 0-9, uppercase A-Z, and lowercase a-z.
package base62

import (
	"io"
	"math/big"
)

// StdAlphabet is the standard base62 alphabet used for encoding and decoding.
// It includes digits 0-9, uppercase letters A-Z, and lowercase letters a-z
// for a total of 62 characters, providing maximum character efficiency.
var StdAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Pre-computed constants for better performance
var (
	bigInt0  = big.NewInt(0)
	bigInt62 = big.NewInt(62)
)

// StdEncoder represents a base62 encoder for standard encoding operations.
// It implements base62 encoding following Python base62 library specifications,
// providing efficient encoding of binary data to base62 strings with proper
// handling of leading zeros.
type StdEncoder struct {
	encodeMap [62]byte // Lookup table for fast encoding of values to characters
	alphabet  string   // The alphabet used for encoding
	Error     error    // Error field for storing encoding errors
}

// NewStdEncoder creates a new base62 encoder using the standard alphabet.
// Initializes the encoding lookup table for efficient character mapping.
func NewStdEncoder() *StdEncoder {
	e := &StdEncoder{alphabet: StdAlphabet}
	copy(e.encodeMap[:], StdAlphabet)
	return e
}

// Encode encodes the given byte slice using base62 encoding.
// Handles leading zeros specially by encoding them as "0" + character pairs.
// The encoding process uses big.Int arithmetic for large number handling.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if len(src) == 0 {
		return
	}

	leadingZerosCount := 0
	for i := 0; i < len(src); i++ {
		if src[i] != 0 {
			break
		}
		leadingZerosCount++
	}

	charsetLen := len(e.encodeMap) - 1
	n := leadingZerosCount / charsetLen
	r := leadingZerosCount % charsetLen

	// Pre-allocate buffer for zero padding to avoid string concatenation
	zeroPaddingLen := n * 2
	if r > 0 {
		zeroPaddingLen += 2
	}
	zeroPadding := make([]byte, 0, zeroPaddingLen)

	for i := 0; i < n; i++ {
		zeroPadding = append(zeroPadding, '0', e.encodeMap[len(e.encodeMap)-1])
	}
	if r > 0 {
		zeroPadding = append(zeroPadding, '0', e.encodeMap[r])
	}

	if leadingZerosCount == len(src) {
		return zeroPadding
	}

	// Convert bytes to big integer (big-endian)
	value := new(big.Int).SetBytes(src)
	encodedValue := e.bigInt2string(value)

	// Pre-allocate result buffer
	result := make([]byte, len(zeroPadding)+len(encodedValue))
	copy(result, zeroPadding)
	copy(result[len(zeroPadding):], encodedValue)

	return result
}

// bigInt2string converts a big.Int to a base62 string representation.
// Uses the standard base62 encoding algorithm with big integer arithmetic.
func (e *StdEncoder) bigInt2string(n *big.Int) []byte {
	// Pre-allocate with estimated capacity (base62 typically produces ~1.37x the input size)
	estimatedSize := n.BitLen() * 137 / 100
	chs := make([]byte, 0, estimatedSize)

	newInt := new(big.Int)

	for n.Cmp(bigInt0) > 0 {
		n.QuoRem(n, bigInt62, newInt)
		chs = append([]byte{e.encodeMap[newInt.Int64()]}, chs...)
	}

	return chs
}

// StdDecoder represents a base62 decoder for standard decoding operations.
// It implements base62 decoding following Python base62 library specifications,
// providing efficient decoding of base62 strings back to binary data with proper
// handling of leading zeros.
type StdDecoder struct {
	decodeMap [256]byte // Lookup table for fast decoding of characters to values
	alphabet  string    // The alphabet used for decoding
	Error     error     // Error field for storing decoding errors
}

// NewStdDecoder creates a new base62 decoder using the standard alphabet.
// Initializes the decoding lookup table for efficient character mapping.
// Invalid characters are marked with 0xFF for error detection.
func NewStdDecoder() *StdDecoder {
	d := &StdDecoder{alphabet: StdAlphabet}
	// Initialize all bytes to 0xFF (invalid)
	for i := 0; i < 256; i++ {
		d.decodeMap[i] = 0xFF
	}
	// Set valid characters
	for i := 0; i < len(StdAlphabet); i++ {
		d.decodeMap[StdAlphabet[i]] = byte(i)
	}
	return d
}

// Decode decodes the given base62-encoded byte slice back to binary data.
// Handles leading zeros pattern ("0" + character) and validates character validity.
// Uses big.Int arithmetic for large number handling.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}

	encoded := string(src)
	var leadingNullBytes []byte

	// Handle leading zeros pattern: "0" + character indicating count
	for len(encoded) >= 2 && encoded[0] == '0' {
		val := int(d.decodeMap[encoded[1]])
		if val < 0 || val >= 62 {
			err = CorruptInputError(1)
			return
		}

		// Pre-allocate leading null bytes to avoid repeated append
		if cap(leadingNullBytes) < len(leadingNullBytes)+val {
			newLeadingNullBytes := make([]byte, len(leadingNullBytes), len(leadingNullBytes)+val)
			copy(newLeadingNullBytes, leadingNullBytes)
			leadingNullBytes = newLeadingNullBytes
		}

		for i := 0; i < val; i++ {
			leadingNullBytes = append(leadingNullBytes, 0)
		}

		encoded = encoded[2:]
	}

	if len(encoded) == 0 {
		return leadingNullBytes, nil
	}

	// Decode the remaining part
	decoded, err := d.string2bigInt(encoded)
	if err != nil {
		return nil, err
	}

	// Convert big integer to bytes
	buf := decoded.Bytes()

	// Combine leading null bytes with decoded bytes
	result := make([]byte, len(leadingNullBytes)+len(buf))
	copy(result, leadingNullBytes)
	copy(result[len(leadingNullBytes):], buf)

	return result, nil
}

// string2bigInt converts a base62 string to a big.Int representation.
// Uses the standard base62 decoding algorithm with big integer arithmetic.
func (d *StdDecoder) string2bigInt(encoded string) (int *big.Int, err error) {
	encodedLen := len(encoded)
	int0 := big.NewInt(0)

	for i, x := range encoded {
		// Check if the character is in the valid range
		if x > 255 {
			err = CorruptInputError(int64(i))
			return
		}
		val := int64(d.decodeMap[byte(x)])
		if val == 0xFF { // Invalid character
			err = CorruptInputError(int64(i))
			return
		}

		power := new(big.Int).Exp(bigInt62, big.NewInt(int64(encodedLen-(i+1))), nil)
		term := new(big.Int).Mul(big.NewInt(val), power)
		int0.Add(int0, term)
	}

	return int0, nil
}

// StreamEncoder represents a streaming base62 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer   io.Writer   // Underlying writer for encoded output
	buffer   []byte      // Buffer for accumulating partial bytes (0-7 bytes)
	alphabet string      // The alphabet used for encoding
	encoder  *StdEncoder // Reuse encoder instance
	Error    error       // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base62 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard base62 alphabet.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{
		writer:   w,
		alphabet: StdAlphabet,
		encoder:  NewStdEncoder(),
		buffer:   make([]byte, 0, 0), // Initialize buffer as empty slice
	}
}

// Write implements the io.Writer interface for streaming base62 encoding.
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

	// Process data in chunks of 8 bytes (optimal for base62 encoding)
	// Base62 encoding typically produces ~1.37x the input size
	chunkSize := 8
	chunks := len(data) / chunkSize

	for i := 0; i < chunks*chunkSize; i += chunkSize {
		chunk := data[i : i+chunkSize]
		encoded := e.encoder.Encode(chunk)
		if e.encoder.Error != nil {
			return len(p), e.encoder.Error
		}
		_, writeErr := e.writer.Write(encoded)
		if writeErr != nil {
			return len(p), writeErr
		}
	}

	// Buffer remaining 0-7 bytes for next write or close
	remainder := len(data) % chunkSize
	if remainder > 0 {
		e.buffer = data[len(data)-remainder:]
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base62 encoding.
// Encodes any remaining buffered bytes from the last Write call.
// This is the only place where we handle cross-Write state.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode any remaining bytes (1-7 bytes) from the last Write
	if len(e.buffer) > 0 {
		encoded := e.encoder.Encode(e.buffer)
		if e.encoder.Error != nil {
			return e.encoder.Error
		}
		_, err := e.writer.Write(encoded)
		if err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming base62 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader   io.Reader   // Underlying reader for encoded input
	buffer   []byte      // Buffer for decoded data not yet read
	pos      int         // Current position in the decoded buffer
	alphabet string      // The alphabet used for decoding
	decoder  *StdDecoder // Reuse decoder instance
	Error    error       // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base62 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard base62 alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{
		reader:   r,
		alphabet: StdAlphabet,
		decoder:  NewStdDecoder(),
	}
}

// Read implements the io.Reader interface for streaming base62 decoding.
// Reads and decodes base62 data from the underlying reader in chunks.
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
	nn, err := d.reader.Read(readBuf)
	if err != nil && err != io.EOF {
		return 0, err
	}

	if nn == 0 {
		return 0, io.EOF
	}

	// Decode the data using the configured decoder
	decoded, decodeErr := d.decoder.Decode(readBuf[:nn])
	if decodeErr != nil {
		return 0, decodeErr
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

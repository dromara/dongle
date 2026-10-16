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
	if e.Error != nil {
		return
	}
	if len(src) == 0 {
		return
	}

	leadingZerosCount := 0
	for i := range src {
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

	for range n {
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
	for i := range 256 {
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
	if d.Error != nil {
		err = d.Error
		return
	}
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

		for range val {
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
	int0 := big.NewInt(0)
	digit := new(big.Int)

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

		int0.Mul(int0, bigInt62)
		int0.Add(int0, digit.SetInt64(val))
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
	}
}

// Write implements the io.Writer interface for streaming base62 encoding.
// Buffers the data; the encoded output is written by Close.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// base62 treats the whole input as one big number, so it cannot be encoded
	// in independent chunks. Buffer everything and encode once in Close.
	e.buffer = append(e.buffer, p...)

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base62 encoding.
// Encodes all data buffered by Write as a single base62 value.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode all buffered input at once
	if len(e.buffer) > 0 {
		encoded := e.encoder.Encode(e.buffer)
		if e.encoder.Error != nil {
			return e.encoder.Error
		}
		if _, err := e.writer.Write(encoded); err != nil {
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
	done     bool        // Whether the encoded input has been read and decoded
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
		if d.pos == len(d.buffer) {
			d.buffer = nil
			d.pos = 0
		}
		return n, nil
	}

	if d.done {
		return 0, io.EOF
	}

	// base62 treats the whole input as one big number, so it cannot be decoded
	// in independent chunks. Read all encoded data and decode it once.
	encoded, err := io.ReadAll(d.reader)
	if err != nil {
		return 0, err
	}
	d.done = true

	if len(encoded) == 0 {
		return 0, io.EOF
	}

	decoded, err := d.decoder.Decode(encoded)
	if err != nil {
		return 0, err
	}

	d.buffer = decoded
	n = copy(p, decoded)
	d.pos = n
	if n == len(decoded) {
		d.buffer = nil
		d.pos = 0
	}
	return n, nil
}

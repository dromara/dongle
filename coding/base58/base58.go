// Package base58 implements base58 encoding and decoding with streaming support.
// It provides base58 encoding following Bitcoin-style specifications,
// using a 58-character alphabet excluding characters that can be confused (0, O, I, l).
package base58

import (
	"io"
	"math/big"
)

// StdAlphabet is the standard base58 alphabet used for encoding and decoding.
// It includes digits 1-9, uppercase letters A-Z (excluding I, O), and lowercase letters a-z (excluding l)
// for a total of 58 characters, providing maximum character efficiency while avoiding confusion.
var StdAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Pre-computed constants for better performance
var (
	bigInt0  = big.NewInt(0)
	bigInt58 = big.NewInt(58)
)

// StdEncoder represents a base58 encoder for standard encoding operations.
// It implements base58 encoding following Bitcoin-style specifications,
// providing efficient encoding of binary data to base58 strings with proper
// handling of leading zeros.
type StdEncoder struct {
	encodeMap [58]byte // Lookup table for fast encoding of values to characters
	alphabet  string   // The alphabet used for encoding
	Error     error    // Error field for storing encoding errors
}

// NewStdEncoder creates a new base58 encoder using the standard alphabet.
// Initializes the encoding lookup table for efficient character mapping.
func NewStdEncoder() *StdEncoder {
	e := &StdEncoder{alphabet: StdAlphabet}
	copy(e.encodeMap[:], StdAlphabet)
	return e
}

// Encode encodes the given byte slice using base58 encoding.
// Handles leading zeros specially by encoding them as leading '1' characters.
// The encoding process uses big.Int arithmetic for large number handling.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if e.Error != nil {
		return
	}
	if len(src) == 0 {
		return
	}

	// Count leading zeros
	leadingZeros := 0
	for _, b := range src {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// If all bytes are zero, return appropriate number of '1's
	if leadingZeros == len(src) {
		result := make([]byte, leadingZeros)
		for i := range result {
			result[i] = '1'
		}
		return result
	}

	// Convert to big.Int, skipping leading zeros
	intBytes := big.NewInt(0).SetBytes(src[leadingZeros:])

	// Pre-allocate dst slice with estimated capacity to avoid reallocations
	// Base58 encoding typically produces ~1.37x the input size
	estimatedSize := (len(src)-leadingZeros)*137/100 + leadingZeros
	dst = make([]byte, 0, estimatedSize)

	// Encode the non-zero part
	for intBytes.Cmp(bigInt0) > 0 {
		var remainder big.Int
		intBytes.DivMod(intBytes, bigInt58, &remainder)
		dst = append(dst, e.encodeMap[remainder.Int64()])
	}

	// Reverse the encoded part
	reverseBytes(dst)

	// Add leading '1's for each leading zero byte
	result := make([]byte, leadingZeros+len(dst))
	for i := 0; i < leadingZeros; i++ {
		result[i] = '1'
	}
	copy(result[leadingZeros:], dst)

	return result
}

// reverseBytes reverses a byte slice in place.
// This is used to correct the order of encoded characters after base58 encoding,
// as the encoding process produces characters in reverse order.
func reverseBytes(b []byte) {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
	}
}

// StdDecoder represents a base58 decoder for standard decoding operations.
// It implements base58 decoding following Bitcoin-style specifications,
// providing efficient decoding of base58 strings back to binary data with proper
// handling of leading zeros.
type StdDecoder struct {
	decodeMap [256]byte // Lookup table for fast decoding of characters to values
	alphabet  string    // The alphabet used for decoding
	Error     error     // Error field for storing decoding errors
}

// NewStdDecoder creates a new base58 decoder using the standard alphabet.
// Initializes the decoding lookup table for efficient character mapping.
// Invalid characters are marked with 0xFF for error detection during decoding.
// The lookup table provides O(1) character validation and value retrieval.
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

// Decode decodes the given base58-encoded byte slice back to binary data.
// Handles leading '1' characters (which represent leading zeros in the original data)
// and validates character validity using the lookup table.
// Uses big.Int arithmetic for large number handling and proper overflow management.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	if len(src) == 0 {
		return
	}

	// Count leading '1's
	leadingOnes := 0
	for _, b := range src {
		if b == '1' {
			leadingOnes++
		} else {
			break
		}
	}

	// If all characters are '1', return appropriate number of zero bytes
	if leadingOnes == len(src) {
		result := make([]byte, leadingOnes)
		return result, nil
	}

	// Decode the non-'1' part
	bigInt := big.NewInt(0)
	for i, v := range src[leadingOnes:] {
		index := int(d.decodeMap[v])
		if index == 0xFF {
			// Invalid character
			return nil, CorruptInputError(i + leadingOnes)
		}
		bigInt.Mul(bigInt, bigInt58)
		bigInt.Add(bigInt, big.NewInt(int64(index)))
	}

	// Convert to bytes
	decodedBytes := bigInt.Bytes()

	// Add leading zeros
	result := make([]byte, leadingOnes+len(decodedBytes))
	copy(result[leadingOnes:], decodedBytes)

	return result, nil
}

// StreamEncoder represents a streaming base58 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer   io.Writer   // Underlying writer for encoded output
	buffer   []byte      // Buffer for accumulating partial bytes (0-7 bytes)
	alphabet string      // The alphabet used for encoding
	encoder  *StdEncoder // Reuse encoder instance
	Error    error       // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base58 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard base58 alphabet.
// Returns an io.WriteCloser that buffers data and performs encoding on Close().
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{
		writer:   w,
		alphabet: StdAlphabet,
		encoder:  NewStdEncoder(),
	}
}

// Write implements the io.Writer interface for streaming base58 encoding.
// Buffers the data; the encoded output is written by Close.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// base58 treats the whole input as one big number, so it cannot be encoded
	// in independent chunks. Buffer everything and encode once in Close.
	e.buffer = append(e.buffer, p...)

	return len(p), nil
}

// Close implements the io.Closer interface for streaming base58 encoding.
// Encodes all data buffered by Write as a single base58 value.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Encode all buffered input at once
	if len(e.buffer) > 0 {
		encoded := e.encoder.Encode(e.buffer)
		if _, err := e.writer.Write(encoded); err != nil {
			return err
		}
		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming base58 decoder that implements io.Reader.
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

// NewStreamDecoder creates a new streaming base58 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard base58 alphabet.
// Returns an io.Reader that provides decoded data in chunks for efficient processing.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{
		reader:   r,
		alphabet: StdAlphabet,
		decoder:  NewStdDecoder(),
	}
}

// Read implements the io.Reader interface for streaming base58 decoding.
// Reads and decodes base58 data from the underlying reader in chunks.
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

	// base58 treats the whole input as one big number, so it cannot be decoded
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

// Encode encodes the given byte slice using base58 encoding.
// This is a convenience function that creates a new encoder and encodes the input.
func Encode(src []byte) (dst []byte) {
	return NewStdEncoder().Encode(src)
}

// Decode decodes the given base58-encoded byte slice back to binary data.
// This is a convenience function that creates a new decoder and decodes the input.
// Returns the decoded data, ignoring any decoding errors.
func Decode(src []byte) []byte {
	dst, _ := NewStdDecoder().Decode(src)
	return dst
}

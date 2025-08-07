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
	alphabet := StdAlphabet
	copy(e.encodeMap[:], alphabet)
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
	int0, int58 := big.NewInt(0), big.NewInt(58)

	// Encode the non-zero part
	for intBytes.Cmp(big.NewInt(0)) > 0 {
		intBytes.DivMod(intBytes, int58, int0)
		dst = append(dst, e.encodeMap[int0.Int64()])
	}

	// Reverse the encoded part
	dst = reverseBytes(dst)

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
func reverseBytes(b []byte) []byte {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
	}
	return b
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
	alphabet := StdAlphabet
	for i := 0; i < 256; i++ {
		d.decodeMap[i] = 0xFF
	}
	for i := 0; i < len(alphabet); i++ {
		d.decodeMap[alphabet[i]] = byte(i)
	}
	return d
}

// Decode decodes the given base58-encoded byte slice back to binary data.
// Handles leading '1' characters (which represent leading zeros in the original data)
// and validates character validity using the lookup table.
// Uses big.Int arithmetic for large number handling and proper overflow management.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
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
		for i := range result {
			result[i] = 0
		}
		return result, nil
	}

	// Decode the non-'1' part
	bigInt := big.NewInt(0)
	for i, v := range src[leadingOnes:] {
		index := int(d.decodeMap[v])
		if index == 0xFF {
			// Invalid character
			return nil, CorruptInputError(int64(i + leadingOnes))
		}
		bigInt.Mul(bigInt, big.NewInt(58))
		bigInt.Add(bigInt, big.NewInt(int64(index)))
	}

	// Convert to bytes
	decodedBytes := bigInt.Bytes()

	// Add leading zeros
	result := make([]byte, leadingOnes+len(decodedBytes))
	for i := 0; i < leadingOnes; i++ {
		result[i] = 0
	}
	copy(result[leadingOnes:], decodedBytes)

	return result, nil
}

// StreamEncoder represents a streaming base58 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by buffering data
// and encoding it when Close() is called, reducing memory usage for large inputs.
type StreamEncoder struct {
	writer   io.Writer // Underlying writer for encoded output
	buffer   []byte    // Buffer for accumulating data before encoding
	alphabet string    // The alphabet used for encoding
	Error    error     // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base58 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard base58 alphabet.
// Returns an io.WriteCloser that buffers data and performs encoding on Close().
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{writer: w, alphabet: StdAlphabet}
}

// Write implements the io.Writer interface for streaming base58 encoding.
// Accumulates data in the internal buffer without immediate encoding.
// The actual encoding occurs when Close() is called to optimize performance
// for large data streams and reduce memory fragmentation.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	e.buffer = append(e.buffer, p...)
	return len(p), nil
}

// Close implements the io.Closer interface for streaming base58 encoding.
// Encodes all buffered data and writes it to the underlying writer.
// This method must be called to complete the encoding process and flush
// any remaining buffered data to the output stream.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}
	if len(e.buffer) > 0 {
		enc := &StdEncoder{}
		copy(enc.encodeMap[:], e.alphabet)
		encoded := enc.Encode(e.buffer)
		_, err := e.writer.Write(encoded)
		return err
	}
	return nil
}

// StreamDecoder represents a streaming base58 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader   io.Reader // Underlying reader for encoded input
	buffer   []byte    // Buffer for decoded data not yet read
	pos      int       // Current position in the decoded buffer
	alphabet string    // The alphabet used for decoding
	Error    error     // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base58 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard base58 alphabet.
// Returns an io.Reader that provides decoded data in chunks for efficient processing.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{reader: r, alphabet: StdAlphabet}
}

// Read implements the io.Reader interface for streaming base58 decoding.
// Reads and decodes base58 data from the underlying reader in chunks.
// Maintains an internal buffer to handle partial reads efficiently and
// provides decoded data to the caller while managing memory usage.
func (d *StreamDecoder) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}
	if d.pos < len(d.buffer) {
		n = copy(p, d.buffer[d.pos:])
		d.pos += n
		return n, nil
	}

	buf := make([]byte, 1024)
	var bufN int
	bufN, err = d.reader.Read(buf)
	if bufN > 0 {
		// Decode the data we just read
		decoded, decodeErr := NewStdDecoder().Decode(buf[:bufN])
		if decodeErr != nil {
			return 0, decodeErr
		}

		// Copy decoded data to output
		n = copy(p, decoded)
		if n < len(decoded) {
			d.buffer = decoded[n:]
			d.pos = 0
		}
		return n, nil
	}

	return 0, err
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

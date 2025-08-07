// Package base85 implements base85 encoding and decoding with streaming support.
// It provides base85 encoding using Go's standard encoding/ascii85 package,
// which implements the ASCII85 encoding as specified in Adobe's PostScript and PDF specifications.
package base85

import (
	"encoding/ascii85"
	"io"
)

// StdEncoder represents a base85 encoder for standard encoding operations.
// It implements base85 encoding using Go's standard encoding/ascii85 package,
// providing efficient encoding of binary data to ASCII85 strings.
type StdEncoder struct {
	Error error // Error field for storing encoding errors
}

// NewStdEncoder creates a new base85 encoder using the standard ASCII85 alphabet.
func NewStdEncoder() *StdEncoder {
	return &StdEncoder{}
}

// Encode encodes the given byte slice using ASCII85 encoding.
// Uses Go's standard encoding/ascii85 package for reliable and efficient encoding.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if len(src) == 0 {
		return
	}

	// Use Go's standard ascii85 encoding
	dst = make([]byte, ascii85.MaxEncodedLen(len(src)))
	n := ascii85.Encode(dst, src)
	return dst[:n]
}

// StdDecoder represents a base85 decoder for standard decoding operations.
// It implements base85 decoding using Go's standard encoding/ascii85 package,
// providing efficient decoding of ASCII85 strings back to binary data.
type StdDecoder struct {
	Error error // Error field for storing decoding errors
}

// NewStdDecoder creates a new base85 decoder using the standard ASCII85 alphabet.
func NewStdDecoder() *StdDecoder {
	return &StdDecoder{}
}

// Decode decodes the given ASCII85-encoded byte slice back to binary data.
// Uses Go's standard encoding/ascii85 package for reliable and efficient decoding.
// Handles special cases like "z" representing 4 zero bytes and incomplete groups.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if len(src) == 0 {
		return
	}

	// Handle special case: "z" represents 4 zero bytes
	if len(src) == 1 && src[0] == 'z' {
		return []byte{0, 0, 0, 0}, nil
	}

	// For incomplete groups, we need to pad to complete 5-character groups
	// Go's ascii85.Decode requires complete groups
	paddedSrc := src
	if len(src)%5 != 0 {
		// Pad with 'u' characters to complete the group
		padding := 5 - (len(src) % 5)
		paddedSrc = make([]byte, len(src)+padding)
		copy(paddedSrc, src)
		for i := len(src); i < len(paddedSrc); i++ {
			paddedSrc[i] = 'u'
		}
	}

	// Use Go's standard ascii85 decoding
	dst = make([]byte, len(paddedSrc)) // ASCII85 decoding can't produce more bytes than input
	n, _, err := ascii85.Decode(dst, paddedSrc, true)
	if err != nil {
		return nil, CorruptInputError(0)
	}

	// Calculate the actual number of bytes based on the original input length
	// For incomplete groups, we need to determine how many bytes were actually encoded
	actualBytes := d.calculateActualBytes(len(src))
	if actualBytes < n {
		return dst[:actualBytes], nil
	}

	return dst[:n], nil
}

// calculateActualBytes calculates the actual number of bytes that were encoded
// based on the number of ASCII85 characters
func (d *StdDecoder) calculateActualBytes(charCount int) int {
	// ASCII85 encoding: 4 bytes -> 5 characters
	// For incomplete groups at the end:
	// 1 char -> 1 byte
	// 2 chars -> 1 byte
	// 3 chars -> 2 bytes
	// 4 chars -> 3 bytes
	// 5 chars -> 4 bytes (complete group)

	// Calculate complete groups first
	completeGroups := charCount / 5
	remainder := charCount % 5

	// Each complete group of 5 chars represents 4 bytes
	totalBytes := completeGroups * 4

	// Add bytes for the remainder
	switch remainder {
	case 1, 2:
		totalBytes += 1
	case 3:
		totalBytes += 2
	case 4:
		totalBytes += 3
	}

	return totalBytes
}

// StreamEncoder represents a streaming base85 encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by buffering data
// and encoding it when Close() is called, reducing memory usage for large inputs.
type StreamEncoder struct {
	writer  io.Writer   // Underlying writer for encoded output
	buffer  []byte      // Buffer for accumulating data before encoding
	encoder *StdEncoder // Encoder instance for consistent encoding
	Error   error       // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming base85 encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard ASCII85 alphabet.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{
		writer:  w,
		encoder: NewStdEncoder(),
	}
}

// Write implements the io.Writer interface for streaming base85 encoding.
// Accumulates data in the internal buffer without immediate encoding.
// The actual encoding occurs when Close() is called.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	e.buffer = append(e.buffer, p...)
	return len(p), nil
}

// Close implements the io.WriteCloser interface for streaming base85 encoding.
// Encodes any remaining data in the buffer and writes it to the underlying writer.
// This method must be called to complete the encoding process.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}
	if len(e.buffer) > 0 {
		encoded := e.encoder.Encode(e.buffer)
		_, err := e.writer.Write(encoded)
		return err
	}
	return nil
}

// StreamDecoder represents a streaming base85 decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader    io.Reader // Underlying reader for encoded input
	buffer    []byte    // Buffer for decoded data not yet read
	pos       int       // Current position in the decoded buffer
	encodeBuf []byte    // Buffer for encoded data not yet decoded
	eof       bool      // Flag to track if we've reached EOF
	Error     error     // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming base85 decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard ASCII85 alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{reader: r}
}

// Read implements the io.Reader interface for streaming base85 decoding.
// Reads and decodes ASCII85 data from the underlying reader in chunks.
// Maintains an internal buffer to handle partial reads efficiently.
func (d *StreamDecoder) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}

	for {
		// First, output any remaining data in the buffer
		if d.pos < len(d.buffer) {
			n = copy(p, d.buffer[d.pos:])
			d.pos += n
			if d.eof && d.pos >= len(d.buffer) {
				return n, io.EOF
			}
			return n, nil
		}

		// Read new data into encodeBuf
		readBuf := make([]byte, 1024)
		bufN, readErr := d.reader.Read(readBuf)
		if bufN > 0 {
			d.encodeBuf = append(d.encodeBuf, readBuf[:bufN]...)
		}
		if readErr == io.EOF {
			d.eof = true
		} else if readErr != nil {
			d.Error = readErr
			return 0, readErr
		}

		// Process encoded data
		if len(d.encodeBuf) > 0 {
			if d.eof {
				// At EOF, decode all remaining data
				decoded, _ := NewStdDecoder().Decode(d.encodeBuf)
				d.buffer = decoded
				d.pos = 0
				d.encodeBuf = nil
				continue // Go back to output buffer
			} else {
				// When not at EOF, only decode complete 5-character groups
				groupCount := len(d.encodeBuf) / 5
				toDecode := groupCount * 5
				if toDecode > 0 {
					decoded, decodeErr := NewStdDecoder().Decode(d.encodeBuf[:toDecode])
					if decodeErr != nil {
						d.Error = decodeErr
						return 0, decodeErr
					}
					d.buffer = decoded
					d.pos = 0
					d.encodeBuf = d.encodeBuf[toDecode:]
					continue // Go back to output buffer
				}
				// No complete groups, wait for more data
				return 0, nil
			}
		}

		// EOF and no more data
		if d.eof && len(d.encodeBuf) == 0 {
			return 0, io.EOF
		}
	}
}

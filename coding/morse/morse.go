// Package morse implements morse encoding and decoding with streaming support.
// It provides morse encoding following the International Morse Code standard (ITU-R M.1677-1).
// Morse code represents text as standardized sequences of dots and dashes.
package morse

import (
	"io"
	"strings"

	"github.com/dromara/dongle/util"
)

var StdSeparator = " "

// StdAlphabet is the standard morse code alphabet following international standards.
// It includes letters a-z, numbers 0-9, and common punctuation marks.
var StdAlphabet = map[string]string{
	"a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
	"g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
	"m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
	"s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
	"y": "-.--", "z": "--..", "0": "-----", "1": ".----", "2": "..---",
	"3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
	"8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
	"!": "-.-.--", "=": "-...-", "+": ".-.-.", "-": "-....-", "/": "-..-.",
}

// StdEncoder represents a morse encoder for standard encoding operations.
// It implements morse encoding following the International Morse Code standard.
type StdEncoder struct {
	alphabet map[string]string // The alphabet used for encoding
	Error    error             // Error field for storing encoding errors
}

// NewStdEncoder creates a new morse encoder using the standard alphabet.
func NewStdEncoder() *StdEncoder {
	return &StdEncoder{alphabet: StdAlphabet}
}

// Encode encodes the given byte slice using morse encoding.
// Converts text to morse code using dots (.) and dashes (-) separated by the specified separator.
// Input text is converted to lowercase before encoding.
func (e *StdEncoder) Encode(src []byte) (dst []byte) {
	if e.Error != nil {
		return
	}
	if len(src) == 0 {
		return
	}

	s := strings.ToLower(util.Bytes2String(src))
	if strings.Contains(s, " ") {
		e.Error = InvalidInputError{}
		return
	}

	// Pre-allocate buffer with estimated size for better performance
	estimatedSize := len(s) * 8 // Average morse code length is ~4 chars + separator
	builder := strings.Builder{}
	builder.Grow(estimatedSize)

	for _, letter := range s {
		let := string(letter)
		if morseCode, exists := e.alphabet[let]; exists {
			builder.WriteString(morseCode)
			builder.WriteString(StdSeparator)
		}
	}

	result := builder.String()
	if len(result) > 0 {
		result = strings.TrimSuffix(result, StdSeparator)
	}
	return []byte(result)
}

// StdDecoder represents a morse decoder for standard decoding operations.
// It implements morse decoding following the International Morse Code standard.
type StdDecoder struct {
	alphabet map[string]string // The alphabet used for decoding
	Error    error             // Error field for storing decoding errors
}

// NewStdDecoder creates a new morse decoder using the standard alphabet.
func NewStdDecoder() *StdDecoder {
	return &StdDecoder{alphabet: StdAlphabet}
}

// Decode decodes the given morse-encoded byte slice back to text.
// Converts morse code (dots and dashes) back to readable text.
// Uses space as the default separator between morse characters.
func (d *StdDecoder) Decode(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		return nil, d.Error
	}
	if len(src) == 0 {
		return
	}

	morseString := util.Bytes2String(src)
	parts := strings.Split(morseString, StdSeparator) // Split by StdSeparator

	// Pre-allocate buffer with estimated size for better performance
	estimatedSize := len(parts) * 2 // Most characters are single letters
	builder := strings.Builder{}
	builder.Grow(estimatedSize)

	for _, part := range parts {
		found := false
		for key, morseCode := range d.alphabet {
			if morseCode == part {
				builder.WriteString(key)
				found = true
				break
			}
		}
		if !found {
			return nil, InvalidCharacterError{Char: part}
		}
	}

	return []byte(builder.String()), nil
}

// StreamEncoder represents a streaming morse encoder that implements io.WriteCloser.
// It provides efficient encoding for large data streams by processing data
// in chunks and writing encoded output immediately.
type StreamEncoder struct {
	writer  io.Writer   // Underlying writer for encoded output
	buffer  []byte      // Buffer for accumulating partial bytes (0-3 bytes)
	encoder *StdEncoder // Reuse encoder instance to avoid repeated creation
	Error   error       // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming morse encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard morse alphabet.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{
		writer:  w,
		encoder: NewStdEncoder(),
		buffer:  make([]byte, 0, 4), // Initialize buffer for potential UTF-8 characters
	}
}

// Write implements the io.Writer interface for streaming morse encoding.
// Processes data character by character for true streaming.
// Each character is immediately encoded and output, maintaining minimal state.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Combine any leftover bytes from previous write with new data
	data := append(e.buffer, p...)
	e.buffer = nil // Clear buffer after combining

	// Check for existing encoder error
	if e.encoder.Error != nil {
		return len(p), e.encoder.Error
	}

	// Process each character individually for true streaming
	var output strings.Builder

	for i, b := range data {
		char := strings.ToLower(string(b))

		// Skip spaces as they're not supported in morse encoding
		if char == " " {
			e.encoder.Error = InvalidInputError{}
			return len(p), e.encoder.Error
		}

		if morseCode, exists := e.encoder.alphabet[char]; exists {
			// Add separator before morse code if not the first character
			if output.Len() > 0 {
				output.WriteString(StdSeparator)
			}
			output.WriteString(morseCode)
		} else {
			// If character is not found, buffer remaining bytes for potential UTF-8 completion
			e.buffer = data[i:]
			break
		}
	}

	// Write the encoded output
	if output.Len() > 0 {
		_, writeErr := e.writer.Write([]byte(output.String()))
		if writeErr != nil {
			return len(p), writeErr
		}
	}

	return len(p), nil
}

// Close implements the io.Closer interface for streaming morse encoding.
// Processes any remaining buffered bytes from the last Write call.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}

	// Process any remaining bytes in the buffer
	if len(e.buffer) > 0 {
		var output strings.Builder

		for _, b := range e.buffer {
			char := strings.ToLower(string(b))

			// Skip spaces as they're not supported in morse encoding
			if char == " " {
				return InvalidInputError{}
			}

			if morseCode, exists := e.encoder.alphabet[char]; exists {
				// Add separator before morse code if not the first character
				if output.Len() > 0 {
					output.WriteString(StdSeparator)
				}
				output.WriteString(morseCode)
			}
		}

		// Write the final encoded output
		if output.Len() > 0 {
			_, err := e.writer.Write([]byte(output.String()))
			if err != nil {
				return err
			}
		}

		e.buffer = nil
	}

	return nil
}

// StreamDecoder represents a streaming morse decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader  io.Reader   // Underlying reader for encoded input
	buffer  []byte      // Buffer for decoded data not yet read
	pos     int         // Current position in the decoded buffer
	decoder *StdDecoder // Reuse decoder instance to avoid repeated creation
	Error   error       // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming morse decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard morse alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{
		reader:  r,
		decoder: NewStdDecoder(),
		buffer:  make([]byte, 0, 1024), // Pre-allocate buffer for decoded data
		pos:     0,
	}
}

// Read implements the io.Reader interface for streaming morse decoding.
// Reads and decodes morse data from the underlying reader in chunks.
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

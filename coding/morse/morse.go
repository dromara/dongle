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

	var builder strings.Builder
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

	var builder strings.Builder
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
// It provides efficient encoding for large data streams by buffering data
// and encoding it when Close() is called.
type StreamEncoder struct {
	writer   io.Writer         // Underlying writer for encoded output
	buffer   []byte            // Buffer for accumulating data before encoding
	alphabet map[string]string // The alphabet used for encoding
	Error    error             // Error field for storing encoding errors
}

// NewStreamEncoder creates a new streaming morse encoder that writes encoded data
// to the provided io.Writer. The encoder uses the standard morse alphabet.
func NewStreamEncoder(w io.Writer) io.WriteCloser {
	return &StreamEncoder{writer: w, alphabet: StdAlphabet}
}

// Write implements the io.Writer interface for streaming morse encoding.
// Accumulates data in the internal buffer without immediate encoding.
// The actual encoding occurs when Close() is called.
func (e *StreamEncoder) Write(p []byte) (n int, err error) {
	if e.Error != nil {
		return 0, e.Error
	}
	e.buffer = append(e.buffer, p...)
	return len(p), nil
}

// Close implements the io.Closer interface for streaming morse encoding.
// Encodes all buffered data and writes it to the underlying writer.
// This method must be called to complete the encoding process.
func (e *StreamEncoder) Close() error {
	if e.Error != nil {
		return e.Error
	}
	if len(e.buffer) > 0 {
		encoder := &StdEncoder{alphabet: e.alphabet}
		encoded := encoder.Encode(e.buffer)
		if encoder.Error != nil {
			return encoder.Error
		}
		_, err := e.writer.Write(encoded)
		return err
	}
	return nil
}

// StreamDecoder represents a streaming morse decoder that implements io.Reader.
// It provides efficient decoding for large data streams by processing data
// in chunks and maintaining an internal buffer for partial reads.
type StreamDecoder struct {
	reader   io.Reader         // Underlying reader for encoded input
	buffer   []byte            // Buffer for decoded data not yet read
	pos      int               // Current position in the decoded buffer
	alphabet map[string]string // The alphabet used for decoding
	Error    error             // Error field for storing decoding errors
}

// NewStreamDecoder creates a new streaming morse decoder that reads encoded data
// from the provided io.Reader. The decoder uses the standard morse alphabet.
func NewStreamDecoder(r io.Reader) io.Reader {
	return &StreamDecoder{reader: r, alphabet: StdAlphabet}
}

// Read implements the io.Reader interface for streaming morse decoding.
// Reads and decodes morse data from the underlying reader in chunks.
// Maintains an internal buffer to handle partial reads efficiently.
func (d *StreamDecoder) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		return 0, d.Error
	}
	if d.pos < len(d.buffer) {
		n = copy(p, d.buffer[d.pos:])
		d.pos += n
		return n, nil
	}

	readBuf := make([]byte, 1024)
	var nn int
	nn, err = d.reader.Read(readBuf)
	if nn > 0 {
		decoder := &StdDecoder{alphabet: d.alphabet}
		decoded, decodeErr := decoder.Decode(readBuf[:nn])
		if decodeErr != nil {
			return 0, decodeErr
		}

		n = copy(p, decoded)
		if n < len(decoded) {
			d.buffer = decoded[n:]
			d.pos = 0
		}
		return n, nil
	}

	return 0, err
}

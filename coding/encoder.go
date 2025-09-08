package coding

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/util"
)

type Encoder struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewEncoder returns a new Encoder instance.
func NewEncoder() *Encoder {
	return &Encoder{}
}

// FromString encodes from string.
func (e *Encoder) FromString(s string) *Encoder {
	e.src = util.String2Bytes(s)
	return e
}

// FromBytes encodes from byte slice.
func (e *Encoder) FromBytes(b []byte) *Encoder {
	e.src = b
	return e
}

func (e *Encoder) FromFile(f fs.File) *Encoder {
	e.reader = f
	return e
}

// ToString outputs as string.
func (e *Encoder) ToString() string {
	return util.Bytes2String(e.dst)
}

// ToBytes outputs as byte slice.
func (e *Encoder) ToBytes() []byte {
	if len(e.dst) == 0 {
		return []byte("")
	}
	return e.dst
}

// stream encodes with stream using true streaming processing.
func (e *Encoder) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	buffer := make([]byte, BufferSize)

	// Create a buffer to collect encoded data
	var result bytes.Buffer

	// Use the provided function to create an encoder
	encoder := fn(&result)
	defer encoder.Close()

	var hasData bool

	// Stream process data in chunks
	for {
		// Read a chunk of data from the reader
		n, err := e.reader.Read(buffer)
		if err != nil && err != io.EOF {
			return []byte{}, err
		}

		// If we read some data, process it immediately
		if n > 0 {
			hasData = true

			// Write the chunk to the encoder for immediate processing
			_, writeErr := encoder.Write(buffer[:n])
			if writeErr != nil {
				return []byte{}, writeErr
			}
		}

		// If we've reached EOF, break the loop
		if err == io.EOF {
			break
		}
	}

	// If no data was read, return empty result
	if !hasData {
		return []byte{}, nil
	}

	// Close the encoder to flush any remaining data
	if err := encoder.Close(); err != nil {
		return []byte{}, err
	}

	// Return the encoded result
	return result.Bytes(), nil
}

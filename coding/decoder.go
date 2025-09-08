package coding

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/util"
)

type Decoder struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewDecoder returns a new Decoder instance.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// FromString decodes from string.
func (d *Decoder) FromString(s string) *Decoder {
	d.src = util.String2Bytes(s)
	return d
}

// FromBytes decodes from byte slice.
func (d *Decoder) FromBytes(b []byte) *Decoder {
	d.src = b
	return d
}

// FromFile decodes from file.
func (d *Decoder) FromFile(ff fs.File) *Decoder {
	d.reader = ff
	return d
}

// ToString outputs as string.
func (d *Decoder) ToString() string {
	return util.Bytes2String(d.dst)
}

// ToBytes outputs as byte slice.
func (d *Decoder) ToBytes() []byte {
	if len(d.dst) == 0 {
		return []byte("")
	}
	return d.dst
}

// stream decodes with stream using true streaming processing.
func (d *Decoder) stream(fn func(io.Reader) io.Reader) ([]byte, error) {
	buffer := make([]byte, BufferSize)

	// Create a buffer to collect decoded data
	var result bytes.Buffer

	// Get the decoder from the provided function
	decoder := fn(d.reader)

	var hasData bool

	// Stream process data in chunks
	for {
		// Read a chunk of data from the decoder
		n, err := decoder.Read(buffer)
		if err != nil && err != io.EOF {
			return []byte{}, err
		}

		// If we read some data, process it immediately
		if n > 0 {
			hasData = true

			// Write the chunk to our result buffer
			// bytes.Buffer.Write never returns an error unless memory runs out
			result.Write(buffer[:n])
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

	// Return the decoded result
	return result.Bytes(), nil
}

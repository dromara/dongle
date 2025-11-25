package coding

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/internal/utils"
)

// Decoder defines a Decoder struct.
type Decoder struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewDecoder returns a new Decoder instance.
func NewDecoder() Decoder {
	return Decoder{}
}

// FromString decodes from string.
func (d Decoder) FromString(s string) Decoder {
	d.src = utils.String2Bytes(s)
	return d
}

// FromBytes decodes from byte slice.
func (d Decoder) FromBytes(b []byte) Decoder {
	d.src = b
	return d
}

// FromFile decodes from file.
func (d Decoder) FromFile(f fs.File) Decoder {
	d.reader = f
	return d
}

// ToString outputs as string.
func (d Decoder) ToString() string {
	if len(d.dst) == 0 || d.Error != nil {
		return ""
	}
	return utils.Bytes2String(d.dst)
}

// ToBytes outputs as byte slice.
func (d Decoder) ToBytes() []byte {
	if len(d.dst) == 0 || d.Error != nil {
		return []byte{}
	}
	return d.dst
}

func (d Decoder) stream(fn func(io.Reader) io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	decoder := fn(d.reader)

	// Try to reset the reader position if it's a seeker
	if seeker, ok := d.reader.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}
	if _, err := io.CopyBuffer(&buf, decoder, make([]byte, BufferSize)); err != nil && err != io.EOF {
		return []byte{}, err
	}
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

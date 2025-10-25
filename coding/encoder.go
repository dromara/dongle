package coding

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/utils"
)

// Encoder defines a Encoder struct.
type Encoder struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewEncoder returns a new Encoder instance.
func NewEncoder() Encoder {
	return Encoder{}
}

// FromString encodes from string.
func (e Encoder) FromString(s string) Encoder {
	e.src = utils.String2Bytes(s)
	return e
}

// FromBytes encodes from byte slice.
func (e Encoder) FromBytes(b []byte) Encoder {
	e.src = b
	return e
}

// FromFile encodes from file.
func (e Encoder) FromFile(f fs.File) Encoder {
	e.reader = f
	return e
}

// ToString outputs as string.
func (e Encoder) ToString() string {
	if len(e.dst) == 0 || e.Error != nil {
		return ""
	}
	return utils.Bytes2String(e.dst)
}

// ToBytes outputs as byte slice.
func (e Encoder) ToBytes() []byte {
	if len(e.dst) == 0 || e.Error != nil {
		return []byte{}
	}
	return e.dst
}

func (e Encoder) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	var buf bytes.Buffer
	encoder := fn(&buf)

	// Try to reset the reader position if it's a seeker
	if seeker, ok := e.reader.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}
	if _, err := io.CopyBuffer(encoder, e.reader, make([]byte, BufferSize)); err != nil && err != io.EOF {
		encoder.Close()
		return []byte{}, err
	}
	if err := encoder.Close(); err != nil {
		return []byte{}, err
	}
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

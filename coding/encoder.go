package coding

import (
	"io"
	"io/fs"

	"gitee.com/golang-package/dongle/utils"
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
	e.src = utils.String2Bytes(s)
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
	return utils.Bytes2String(e.dst)
}

// ToBytes outputs as byte slice.
func (e *Encoder) ToBytes() []byte {
	if len(e.dst) == 0 {
		return []byte("")
	}
	return e.dst
}

// stream encodes with stream.
func (e *Encoder) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		encoder := fn(pw)
		defer encoder.Close()
		_, err := io.Copy(encoder, e.reader)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
	}()
	// Read all encoded data
	return io.ReadAll(pr)
}

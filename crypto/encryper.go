package crypto

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/utils"
)

type Encrypter struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewEncrypter returns a new Encrypter instance.
func NewEncrypter() Encrypter {
	return Encrypter{}
}

// FromString encrypts from string.
func (e Encrypter) FromString(s string) Encrypter {
	e.src = utils.String2Bytes(s)
	return e
}

// FromBytes encrypts from byte slice.
func (e Encrypter) FromBytes(b []byte) Encrypter {
	e.src = b
	return e
}

// FromFile encrypts from file.
func (e Encrypter) FromFile(f fs.File) Encrypter {
	e.reader = f
	return e
}

// ToRawString outputs as raw string.
func (e Encrypter) ToRawString() string {
	return utils.Bytes2String(e.dst)
}

// ToRawBytes outputs as raw byte slice.
func (e Encrypter) ToRawBytes() []byte {
	if len(e.dst) == 0 {
		return []byte{}
	}
	return e.dst
}

// ToBase64String outputs as base64 string.
func (e Encrypter) ToBase64String() string {
	return coding.NewEncoder().FromBytes(e.dst).ByBase64().ToString()
}

// ToBase64Bytes outputs as base64 byte slice.
func (e Encrypter) ToBase64Bytes() []byte {
	return coding.NewEncoder().FromBytes(e.dst).ByBase64().ToBytes()
}

// ToHexString outputs as hex string.
func (e Encrypter) ToHexString() string {
	return coding.NewEncoder().FromBytes(e.dst).ByHex().ToString()
}

// ToHexBytes outputs as hex byte slice.
func (e Encrypter) ToHexBytes() []byte {
	return coding.NewEncoder().FromBytes(e.dst).ByHex().ToBytes()
}

func (e Encrypter) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	var buf bytes.Buffer
	encrypter := fn(&buf)

	// Try to reset the reader position if it's a seeker
	if seeker, ok := e.reader.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}
	if _, err := io.CopyBuffer(encrypter, e.reader, make([]byte, BufferSize)); err != nil && err != io.EOF {
		encrypter.Close()
		return []byte{}, err
	}
	if err := encrypter.Close(); err != nil {
		return []byte{}, err
	}
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

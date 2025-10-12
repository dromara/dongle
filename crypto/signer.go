package crypto

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/utils"
)

type Signer struct {
	data   []byte
	sign   []byte
	reader io.Reader
	Error  error
}

// NewSigner returns a new Signer instance.
func NewSigner() Signer {
	return Signer{}
}

// FromString signs from string.
func (s Signer) FromString(str string) Signer {
	s.data = utils.String2Bytes(str)
	return s
}

// FromBytes signs from byte slice.
func (s Signer) FromBytes(b []byte) Signer {
	s.data = b
	return s
}

// FromFile signs from file.
func (s Signer) FromFile(f fs.File) Signer {
	s.reader = f
	return s
}

// ToRawString outputs as raw string.
func (s Signer) ToRawString() string {
	return utils.Bytes2String(s.sign)
}

// ToRawBytes outputs as raw byte slice.
func (s Signer) ToRawBytes() []byte {
	if len(s.data) == 0 {
		return []byte{}
	}
	return s.sign
}

// ToBase64String outputs as base64 string.
func (s Signer) ToBase64String() string {
	return coding.NewEncoder().FromBytes(s.sign).ByBase64().ToString()
}

// ToBase64Bytes outputs as base64 byte slice.
func (s Signer) ToBase64Bytes() []byte {
	return coding.NewEncoder().FromBytes(s.sign).ByBase64().ToBytes()
}

// ToHexString outputs as hex string.
func (s Signer) ToHexString() string {
	return coding.NewEncoder().FromBytes(s.sign).ByHex().ToString()
}

// ToHexBytes outputs as hex byte slice.
func (s Signer) ToHexBytes() []byte {
	return coding.NewEncoder().FromBytes(s.sign).ByHex().ToBytes()
}

func (s Signer) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	var buf bytes.Buffer
	signer := fn(&buf)

	// Try to reset the reader position if it's a seeker
	if seeker, ok := s.reader.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}

	if _, err := io.CopyBuffer(signer, s.reader, make([]byte, BufferSize)); err != nil && err != io.EOF {
		signer.Close()
		return []byte{}, err
	}
	if err := signer.Close(); err != nil {
		return []byte{}, err
	}
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

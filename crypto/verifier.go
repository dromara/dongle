package crypto

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/utils"
)

type Verifier struct {
	data   []byte
	sign   []byte
	reader io.Reader
	Error  error
}

// NewVerifier returns a new Verifier instance.
func NewVerifier() Verifier {
	return Verifier{}
}

// FromString verifies from string.
func (v Verifier) FromString(s string) Verifier {
	v.data = utils.String2Bytes(s)
	return v
}

// FromBytes verifies from byte slice.
func (v Verifier) FromBytes(b []byte) Verifier {
	v.data = b
	return v
}

// FromFile verifies from file.
func (v Verifier) FromFile(f fs.File) Verifier {
	v.reader = f
	return v
}

// WithHexSign verifies with hex sign.
func (v Verifier) WithHexSign(s []byte) Verifier {
	v.sign = coding.NewDecoder().FromBytes(s).ByHex().ToBytes()
	return v
}

// WithBase64Sign verifies with base64 sign.
func (v Verifier) WithBase64Sign(s []byte) Verifier {
	v.sign = coding.NewDecoder().FromBytes(s).ByBase64().ToBytes()
	return v
}

// WithRawSign verifies with raw sign.
func (v Verifier) WithRawSign(s []byte) Verifier {
	v.sign = s
	return v
}

// ToBool returns true if verification is successful.
func (v Verifier) ToBool() bool {
	if len(v.data) == 0 || len(v.sign) == 0 {
		return false
	}
	return v.Error == nil
}

func (v Verifier) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	var buf bytes.Buffer
	verifier := fn(&buf)

	// Try to reset the reader position if it's a seeker
	if seeker, ok := v.reader.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}
	if _, err := io.CopyBuffer(verifier, v.reader, make([]byte, BufferSize)); err != nil && err != io.EOF {
		verifier.Close()
		return []byte{}, err
	}
	if err := verifier.Close(); err != nil {
		return []byte{}, err
	}
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

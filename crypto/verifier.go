package crypto

import (
	"io"
	"io/fs"

	"github.com/dromara/dongle/util"
)

type Verifier struct {
	data   []byte
	sign   []byte
	reader io.Reader
	Error  error
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (v *Verifier) FromString(s string) *Verifier {
	v.data = util.String2Bytes(s)
	return v
}

func (v *Verifier) FromBytes(b []byte) *Verifier {
	v.data = b
	return v
}

func (v *Verifier) FromFile(f fs.File) *Verifier {
	v.reader = f
	return v
}

func (v *Verifier) ToBool() bool {
	if len(v.data) == 0 || len(v.sign) == 0 {
		return false
	}
	return v.Error == nil
}

// stream signs with crypto stream.
func (v *Verifier) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	// Check if reader is nil
	if v.reader == nil {
		return nil, io.ErrUnexpectedEOF
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		// Create a WriteCloser that signs data
		verifier := fn(pw)
		defer verifier.Close()

		// Use a buffer to avoid direct io.Copy issues with certain readers
		buffer := make([]byte, 4096)
		for {
			n, err := v.reader.Read(buffer)
			if n > 0 {
				_, writeErr := verifier.Write(buffer[:n])
				if writeErr != nil {
					pw.CloseWithError(writeErr)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					pw.CloseWithError(err)
				}
				return
			}
		}
	}()

	// Read all signed data
	return io.ReadAll(pr)
}

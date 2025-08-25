package crypto

import (
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/util"
)

type Signer struct {
	data   []byte
	sign   []byte
	reader io.Reader
	Error  error
}

// NewSigner returns a new Signer instance.
func NewSigner() *Signer {
	return &Signer{}
}

func (s *Signer) FromString(str string) *Signer {
	s.data = util.String2Bytes(str)
	return s
}

func (s *Signer) FromBytes(b []byte) *Signer {
	s.data = b
	return s
}

func (s *Signer) FromFile(f fs.File) *Signer {
	s.reader = f
	return s
}

// ToRawString outputs as raw string without encoding.
func (s *Signer) ToRawString() string {
	return util.Bytes2String(s.sign)
}

// ToRawBytes outputs as raw byte slice without encoding.
func (s *Signer) ToRawBytes() []byte {
	return s.sign
}

// ToBase64String outputs as base64 string.
func (s *Signer) ToBase64String() string {
	return coding.NewEncoder().FromBytes(s.sign).ByBase64().ToString()
}

// ToBase64Bytes outputs as base64 byte slice.
func (s *Signer) ToBase64Bytes() []byte {
	return coding.NewEncoder().FromBytes(s.sign).ByBase64().ToBytes()
}

// ToHexString outputs as hex string.
func (s *Signer) ToHexString() string {
	return coding.NewEncoder().FromBytes(s.sign).ByHex().ToString()
}

// ToHexBytes outputs as hex byte slice.
func (s *Signer) ToHexBytes() []byte {
	return coding.NewEncoder().FromBytes(s.sign).ByHex().ToBytes()
}

// stream signs with crypto stream.
func (s *Signer) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		// Create a WriteCloser that signs data
		signer := fn(pw)
		defer signer.Close()

		// Use a buffer to avoid direct io.Copy issues with certain readers
		buffer := make([]byte, 4096)
		for {
			n, err := s.reader.Read(buffer)
			if n > 0 {
				_, writeErr := signer.Write(buffer[:n])
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

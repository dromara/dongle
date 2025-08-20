package crypto

import (
	"io"
	"io/fs"

	"gitee.com/golang-package/dongle/coding"
	"gitee.com/golang-package/dongle/utils"
)

type Encrypter struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewEncrypter returns a new Encrypter instance.
func NewEncrypter() *Encrypter {
	return &Encrypter{}
}

// FromString encodes from string.
func (e *Encrypter) FromString(s string) *Encrypter {
	e.src = utils.String2Bytes(s)
	return e
}

// FromBytes encodes from byte slice.
func (e *Encrypter) FromBytes(b []byte) *Encrypter {
	e.src = b
	return e
}

func (e *Encrypter) FromFile(f fs.File) *Encrypter {
	e.reader = f
	return e
}

// ToRawString outputs as raw string without encoding.
func (e *Encrypter) ToRawString() string {
	return utils.Bytes2String(e.dst)
}

// ToRawBytes outputs as raw byte slice without encoding.
func (e *Encrypter) ToRawBytes() []byte {
	return e.dst
}

// ToBase64String outputs as base64 string.
func (e *Encrypter) ToBase64String() string {
	return coding.NewEncoder().FromBytes(e.dst).ByBase64().ToString()
}

// ToBase64Bytes outputs as base64 byte slice.
func (e *Encrypter) ToBase64Bytes() []byte {
	return coding.NewEncoder().FromBytes(e.dst).ByBase64().ToBytes()
}

// ToHexString outputs as hex string.
func (e *Encrypter) ToHexString() string {
	return coding.NewEncoder().FromBytes(e.dst).ByHex().ToString()
}

// ToHexBytes outputs as hex byte slice.
func (e *Encrypter) ToHexBytes() []byte {
	return coding.NewEncoder().FromBytes(e.dst).ByHex().ToBytes()
}

// streamCrypto encrypts with crypto stream.
func (e *Encrypter) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		// Create a WriteCloser that encrypts data
		encrypter := fn(pw)
		defer encrypter.Close()

		// Use a buffer to avoid direct io.Copy issues with certain readers
		buffer := make([]byte, 4096)
		for {
			n, err := e.reader.Read(buffer)
			if n > 0 {
				_, writeErr := encrypter.Write(buffer[:n])
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
	// Read all encrypted data
	return io.ReadAll(pr)
}

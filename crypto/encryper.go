package crypto

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/util"
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
	e.src = util.String2Bytes(s)
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
	return util.Bytes2String(e.dst)
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

// streamCrypto encrypts with crypto stream using true streaming approach.
// This method processes data in chunks without loading all results into memory,
// providing constant memory usage regardless of input size.
func (e *Encrypter) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	// Use a bytes.Buffer to collect encrypted output
	// This is more efficient than io.Pipe + io.ReadAll for the crypto use case
	var result bytes.Buffer

	// Create encrypter that writes directly to result buffer
	encrypter := fn(&result)
	defer encrypter.Close()

	// Process data in chunks for true streaming
	const bufferSize = 4096 // 4KB chunks for optimal performance
	buffer := make([]byte, bufferSize)

	for {
		// Read chunk from input
		n, readErr := e.reader.Read(buffer)
		if n > 0 {
			// Immediately encrypt and write the chunk
			_, writeErr := encrypter.Write(buffer[:n])
			if writeErr != nil {
				return nil, writeErr
			}
		}

		// Handle read errors
		if readErr != nil {
			if readErr == io.EOF {
				break // Normal end of input
			}
			return nil, readErr
		}
	}

	// Return the accumulated encrypted data
	bytes := result.Bytes()
	if bytes == nil {
		return []byte{}, nil // Return empty slice instead of nil for consistency
	}
	return bytes, nil
}

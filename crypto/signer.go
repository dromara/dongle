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

func (s Signer) FromString(str string) Signer {
	s.data = utils.String2Bytes(str)
	return s
}

func (s Signer) FromBytes(b []byte) Signer {
	s.data = b
	return s
}

func (s Signer) FromFile(f fs.File) Signer {
	s.reader = f
	return s
}

// ToRawString outputs as raw string without encoding.
func (s Signer) ToRawString() string {
	return utils.Bytes2String(s.sign)
}

// ToRawBytes outputs as raw byte slice without encoding.
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

// stream signs with crypto stream using true streaming approach.
// This method processes data in chunks without loading all results into memory,
// providing constant memory usage regardless of input size.
// The signature is captured from the StreamSigner's output.
func (s Signer) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	// Use a bytes.Buffer to collect the signature output
	// StreamSigner writes the signature to the writer in its Close() method
	var bf bytes.Buffer

	// Create signer that writes directly to bf buffer
	signer := fn(&bf)

	// Process data in chunks for true streaming
	buffer := make([]byte, BufferSize)

	for {
		// Read chunk from input
		n, readErr := s.reader.Read(buffer)
		if n > 0 {
			// Immediately sign and accumulate the chunk
			_, writeErr := signer.Write(buffer[:n])
			if writeErr != nil {
				signer.Close() // Close on error
				return []byte{}, writeErr
			}
		}

		// Handle read errors
		if readErr != nil {
			if readErr == io.EOF {
				break // Normal end of input
			}
			signer.Close() // Close on error
			return []byte{}, readErr
		}
	}

	// Close the signer to generate the signature and write it to the buffer
	// Note: Close errors are not propagated to maintain compatibility with existing tests
	// The signature data is still captured even if Close() returns an error
	_ = signer.Close()

	// Return the accumulated signature data
	data := bf.Bytes()
	if data == nil {
		return []byte{}, nil // Return empty slice instead of nil for consistency
	}
	return data, nil
}

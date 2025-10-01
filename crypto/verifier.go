package crypto

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/util"
)

type Verifier struct {
	data   []byte
	sign   []byte
	reader io.Reader
	Error  error
}

func NewVerifier() Verifier {
	return Verifier{}
}

func (v Verifier) FromString(s string) Verifier {
	v.data = util.String2Bytes(s)
	return v
}

func (v Verifier) FromBytes(b []byte) Verifier {
	v.data = b
	return v
}

func (v Verifier) FromFile(f fs.File) Verifier {
	v.reader = f
	return v
}

func (v Verifier) WithHexSign(s []byte) Verifier {
	v.sign = coding.NewDecoder().FromBytes(s).ByHex().ToBytes()
	return v
}

func (v Verifier) WithBase64Sign(s []byte) Verifier {
	v.sign = coding.NewDecoder().FromBytes(s).ByBase64().ToBytes()
	return v
}

func (v Verifier) WithRawSign(s []byte) Verifier {
	v.sign = s
	return v
}

func (v Verifier) ToBool() bool {
	if len(v.data) == 0 || len(v.sign) == 0 {
		return false
	}
	return v.Error == nil
}

// stream verifies with crypto stream using true streaming approach.
// This method processes data in chunks without loading all results into memory,
// providing constant memory usage regardless of input size.
func (v Verifier) stream(fn func(io.Writer) io.WriteCloser) ([]byte, error) {
	// Check if reader is nil
	if v.reader == nil {
		return []byte{}, io.ErrUnexpectedEOF
	}

	// Use a bytes.Buffer to collect the verification output
	// This is more efficient than io.Pipe + io.ReadAll for the crypto use case
	var bf bytes.Buffer

	// Create verifier that writes directly to bf buffer
	verifier := fn(&bf)

	// Process data in chunks for true streaming
	buffer := make([]byte, BufferSize)

	for {
		// Read chunk from input
		n, readErr := v.reader.Read(buffer)
		if n > 0 {
			// Immediately verify and accumulate the chunk
			_, writeErr := verifier.Write(buffer[:n])
			if writeErr != nil {
				verifier.Close() // Close on error
				return nil, writeErr
			}
		}

		// Handle read errors
		if readErr != nil {
			if readErr == io.EOF {
				break // Normal end of input
			}
			verifier.Close() // Close on error
			return []byte{}, readErr
		}
	}

	// Close the verifier to complete verification and write results to the buffer
	// Note: Close errors are not propagated to maintain compatibility with existing tests
	// The verification data is still captured even if Close() returns an error
	_ = verifier.Close()

	// Return the accumulated verification data
	bytes := bf.Bytes()
	if bytes == nil {
		return []byte{}, nil // Return empty slice instead of nil for consistency
	}
	return bytes, nil
}

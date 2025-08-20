package crypto

import (
	"bytes"
	"fmt"
	"io"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/utils"
)

type Verifier struct {
	src    []byte
	sign   []byte
	reader io.Reader
	Error  error
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (v *Verifier) FromRawString(s string) *Verifier {
	v.src = utils.String2Bytes(s)
	return v
}

func (v *Verifier) FromRawBytes(b []byte) *Verifier {
	v.src = b
	return v
}

func (v *Verifier) FromBase64String(s string) *Verifier {
	decode := coding.NewDecoder().FromString(s).ByBase64()
	if decode.Error != nil {
		return v
	}
	v.src = decode.ToBytes()
	return v
}

func (v *Verifier) FromBase64Bytes(b []byte) *Verifier {
	decode := coding.NewDecoder().FromBytes(b).ByBase64()
	if decode.Error != nil {
		return v
	}
	v.src = decode.ToBytes()
	return v
}

func (v *Verifier) FromHexString(s string) *Verifier {
	decode := coding.NewDecoder().FromString(s).ByHex()
	if decode.Error != nil {
		return v
	}
	v.src = decode.ToBytes()
	return v
}

func (v *Verifier) FromHexBytes(b []byte) *Verifier {
	decode := coding.NewDecoder().FromBytes(b).ByHex()
	if decode.Error != nil {
		return v
	}
	v.src = decode.ToBytes()
	return v
}

func (v *Verifier) ToBool() bool {
	if len(v.src) == 0 || len(v.sign) == 0 {
		return false
	}
	return v.Error == nil
}

// stream verifies with crypto stream.
// Note: This is a simplified implementation for RSA verification.
// In practice, streaming verification for RSA is complex as it requires
// both the data and signature to be available.
func (v *Verifier) stream(fn func(io.Reader) io.Reader) ([]byte, error) {
	// For RSA verification, we need both the data and signature
	// This is a simplified implementation that reads all data first
	if v.reader == nil {
		return nil, fmt.Errorf("no reader available for streaming verification")
	}

	// Read all data from the reader
	data, err := io.ReadAll(v.reader)
	if err != nil {
		return nil, err
	}

	// Create a reader from the data
	dataReader := bytes.NewReader(data)

	// Create a verifier reader
	verifierReader := fn(dataReader)

	// Read the verification result
	result, err := io.ReadAll(verifierReader)
	if err != nil {
		return nil, err
	}

	return result, nil
}

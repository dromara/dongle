package crypto

import (
	"bytes"
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/coding/base64"
	"github.com/dromara/dongle/coding/hex"
	"github.com/dromara/dongle/utils"
)

type Decrypter struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewDecrypter returns a new Decrypter instance.
func NewDecrypter() Decrypter {
	return Decrypter{}
}

// FromRawString decrypts from raw string.
func (d Decrypter) FromRawString(s string) Decrypter {
	d.src = utils.String2Bytes(s)
	return d
}

// FromRawBytes decrypts from raw bytes.
func (d Decrypter) FromRawBytes(b []byte) Decrypter {
	d.src = b
	return d
}

// FromRawFile decrypts from raw file.
func (d Decrypter) FromRawFile(f fs.File) Decrypter {
	d.reader = f
	return d
}

// FromBase64String decrypts from base64 string.
func (d Decrypter) FromBase64String(s string) Decrypter {
	decode := coding.NewDecoder().FromString(s).ByBase64()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

// FromBase64Bytes decrypts from base64 bytes.
func (d Decrypter) FromBase64Bytes(b []byte) Decrypter {
	decode := coding.NewDecoder().FromBytes(b).ByBase64()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

// FromBase64File decrypts from base64 file.
func (d Decrypter) FromBase64File(f fs.File) Decrypter {
	if d.Error != nil {
		return d
	}

	src, err := io.ReadAll(base64.NewStreamDecoder(f, base64.StdAlphabet))
	if err != nil {
		d.Error = err
		return d
	}

	d.src = src
	return d
}

// FromHexString decrypts from hex string.
func (d Decrypter) FromHexString(s string) Decrypter {
	decode := coding.NewDecoder().FromString(s).ByHex()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

// FromHexBytes decrypts from hex bytes.
func (d Decrypter) FromHexBytes(b []byte) Decrypter {
	decode := coding.NewDecoder().FromBytes(b).ByHex()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

// FromHexFile decrypts from hex file.
func (d Decrypter) FromHexFile(f fs.File) Decrypter {
	if d.Error != nil {
		return d
	}

	src, err := io.ReadAll(hex.NewStreamDecoder(f))
	if err != nil {
		d.Error = err
		return d
	}

	d.src = src
	return d
}

// ToString outputs as string.
func (d Decrypter) ToString() string {
	return utils.Bytes2String(d.dst)
}

// ToBytes outputs as byte slice.
func (d Decrypter) ToBytes() []byte {
	if len(d.dst) == 0 {
		return []byte{}
	}
	return d.dst
}

func (d Decrypter) stream(fn func(io.Reader) io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	decrypter := fn(d.reader)

	if _, err := io.CopyBuffer(&buf, decrypter, make([]byte, BufferSize)); err != nil && err != io.EOF {
		return []byte{}, err
	}
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

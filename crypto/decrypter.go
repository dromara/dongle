package crypto

import (
	"io"
	"io/fs"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/coding/base64"
	"github.com/dromara/dongle/coding/hex"
	"github.com/dromara/dongle/util"
)

type Decrypter struct {
	src    []byte
	dst    []byte
	reader io.Reader
	Error  error
}

// NewDecrypter returns a new Decrypter instance.
func NewDecrypter() *Decrypter {
	return &Decrypter{}
}

func (d *Decrypter) FromRawString(s string) *Decrypter {
	d.src = util.String2Bytes(s)
	return d
}

func (d *Decrypter) FromRawBytes(b []byte) *Decrypter {
	d.src = b
	return d
}

func (d *Decrypter) FromRawFile(f fs.File) *Decrypter {
	d.reader = f
	return d
}

func (d *Decrypter) FromBase64String(s string) *Decrypter {
	decode := coding.NewDecoder().FromString(s).ByBase64()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

func (d *Decrypter) FromBase64Bytes(b []byte) *Decrypter {
	decode := coding.NewDecoder().FromBytes(b).ByBase64()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

func (d *Decrypter) FromBase64File(f fs.File) *Decrypter {
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

func (d *Decrypter) FromHexString(s string) *Decrypter {
	decode := coding.NewDecoder().FromString(s).ByHex()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

func (d *Decrypter) FromHexBytes(b []byte) *Decrypter {
	decode := coding.NewDecoder().FromBytes(b).ByHex()
	if decode.Error != nil {
		return d
	}
	d.src = decode.ToBytes()
	return d
}

func (d *Decrypter) FromHexFile(f fs.File) *Decrypter {
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
func (d *Decrypter) ToString() string {
	return util.Bytes2String(d.dst)
}

// ToBytes outputs as byte slice.
func (d *Decrypter) ToBytes() []byte {
	if len(d.dst) == 0 {
		return []byte("")
	}
	return d.dst
}

// stream decrypts with crypto stream.
func (d *Decrypter) stream(fn func(io.Reader) io.Reader) ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		// Create a Reader that decrypts data
		decrypter := fn(d.reader)
		_, err := io.Copy(pw, decrypter)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
	}()
	// Read all decrypted data
	return io.ReadAll(pr)
}

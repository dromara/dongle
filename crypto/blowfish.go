package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/blowfish"
	"github.com/dromara/dongle/crypto/cipher"
)

func (e *Encrypter) ByBlowfish(c cipher.CipherInterface) *Encrypter {
	if e.Error != nil {
		return e
	}

	// Get the key from the cipher configuration
	var key []byte
	if keyGetter, ok := c.(cipher.KeyGetter); ok {
		key = keyGetter.GetKey()
	} else {
		e.Error = blowfish.KeyUnsetError{}
		return e
	}

	// Check if we have a reader (streaming mode)
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return blowfish.NewStreamEncrypter(w, c, key)
		})
		return e
	}

	// Standard encryption mode
	encrypted, err := blowfish.NewStdEncrypter(c, key).Encrypt(e.src)
	if err != nil {
		e.Error = err
		return e
	}

	e.dst = encrypted
	return e
}

func (d *Decrypter) ByBlowfish(c cipher.CipherInterface) *Decrypter {
	if d.Error != nil {
		return d
	}

	// Get the key from the cipher configuration
	var key []byte
	if keyGetter, ok := c.(cipher.KeyGetter); ok {
		key = keyGetter.GetKey()
	} else {
		d.Error = blowfish.KeyUnsetError{}
		return d
	}

	// Check if we have a reader (streaming mode)
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return blowfish.NewStreamDecrypter(r, c, key)
		})
		return d
	}

	// Standard decryption mode
	decrypted, err := blowfish.NewStdDecrypter(c, key).Decrypt(d.src)
	if err != nil {
		d.Error = err
		return d
	}

	d.dst = decrypted
	return d
}

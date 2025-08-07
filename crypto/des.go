package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/des"
)

func (e *Encrypter) ByDes(c cipher.CipherInterface) *Encrypter {
	if e.Error != nil {
		return e
	}

	// Get the key from the cipher configuration
	var key []byte
	if keyGetter, ok := c.(cipher.KeyGetter); ok {
		key = keyGetter.GetKey()
	} else {
		e.Error = des.KeyUnsetError{}
		return e
	}

	// Check if we have a reader (streaming mode)
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return des.NewStreamEncrypter(w, c, key)
		})
		return e
	}

	// Standard encryption mode
	enc := des.NewStdEncrypter(c, key)
	if enc.Error != nil {
		e.Error = enc.Error
		return e
	}

	encrypted, err := enc.Encrypt(e.src)
	if err != nil {
		e.Error = err
		return e
	}

	e.dst = encrypted
	return e
}

func (d *Decrypter) ByDes(c cipher.CipherInterface) *Decrypter {
	if d.Error != nil {
		return d
	}

	// Get the key from the cipher configuration
	var key []byte
	if keyGetter, ok := c.(cipher.KeyGetter); ok {
		key = keyGetter.GetKey()
	} else {
		d.Error = des.KeyUnsetError{}
		return d
	}

	// Check if we have a reader (streaming mode)
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return des.NewStreamDecrypter(r, c, key)
		})
		return d
	}

	// Standard decryption mode
	decrypted, err := des.NewStdDecrypter(c, key).Decrypt(d.src)
	if err != nil {
		d.Error = err
		return d
	}

	d.dst = decrypted
	return d
}

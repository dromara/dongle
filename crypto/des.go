package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/des"
)

func (e Encrypter) ByDes(c *cipher.DesCipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Check if we have a reader (streaming mode)
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return des.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	enc := des.NewStdEncrypter(c)
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

func (d Decrypter) ByDes(c *cipher.DesCipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Check if we have a reader (streaming mode)
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return des.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	decrypted, err := des.NewStdDecrypter(c).Decrypt(d.src)
	if err != nil {
		d.Error = err
		return d
	}

	d.dst = decrypted
	return d
}

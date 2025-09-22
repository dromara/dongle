package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/aes"
	"github.com/dromara/dongle/crypto/cipher"
)

func (e Encrypter) ByAes(c *cipher.AesCipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Check if we have a reader (streaming mode)
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return aes.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	encrypted, err := aes.NewStdEncrypter(c).Encrypt(e.src)
	if err != nil {
		e.Error = err
		return e
	}

	e.dst = encrypted
	return e
}

func (d Decrypter) ByAes(c *cipher.AesCipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Check if we have a reader (streaming mode)
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return aes.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	decrypted, err := aes.NewStdDecrypter(c).Decrypt(d.src)
	if err != nil {
		d.Error = err
		return d
	}

	d.dst = decrypted
	return d
}

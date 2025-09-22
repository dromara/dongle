package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/salsa20"
)

// BySalsa20 encrypts by Salsa20.
func (e Encrypter) BySalsa20(c *cipher.Salsa20Cipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// If reader is set, use streaming processing
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return salsa20.NewStreamEncrypter(w, c)
		})
		return e
	}

	if len(e.src) > 0 {
		e.dst, e.Error = salsa20.NewStdEncrypter(c).Encrypt(e.src)
	}
	return e
}

// BySalsa20 decrypts by Salsa20.
func (d Decrypter) BySalsa20(c *cipher.Salsa20Cipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// If reader is set, use streaming processing
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return salsa20.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Decrypt data in memory
	if len(d.src) > 0 {
		d.dst, d.Error = salsa20.NewStdDecrypter(c).Decrypt(d.src)
	}
	return d
}

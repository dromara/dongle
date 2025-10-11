package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/rc4"
)

// ByRc4 encrypts by rc4.
func (e Encrypter) ByRc4(c *cipher.Rc4Cipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return rc4.NewStreamEncrypter(w, c.Key)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = rc4.NewStdEncrypter(c.Key).Encrypt(e.src)
	}

	return e
}

// ByRc4 decrypts by rc4.
func (d Decrypter) ByRc4(c *cipher.Rc4Cipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return rc4.NewStreamDecrypter(r, c.Key)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = rc4.NewStdDecrypter(c.Key).Decrypt(d.src)
	}

	return d
}

package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/sm4"
)

// BySm4 encrypts by sm4.
func (e Encrypter) BySm4(c *cipher.Sm4Cipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return sm4.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		encrypter := sm4.NewStdEncrypter(c)
		if encrypter.Error != nil {
			e.Error = encrypter.Error
			return e
		}
		e.dst, e.Error = encrypter.Encrypt(e.src)
	}
	return e
}

// BySm4 decrypts by sm4.
func (d Decrypter) BySm4(c *cipher.Sm4Cipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return sm4.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		decrypter := sm4.NewStdDecrypter(c)
		if decrypter.Error != nil {
			d.Error = decrypter.Error
			return d
		}
		d.dst, d.Error = decrypter.Decrypt(d.src)
	}

	return d
}

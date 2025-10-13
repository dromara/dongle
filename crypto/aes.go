package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/aes"
	"github.com/dromara/dongle/crypto/cipher"
)

// ByAes encrypts by aes.
func (e Encrypter) ByAes(c *cipher.AesCipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return aes.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = aes.NewStdEncrypter(c).Encrypt(e.src)
	}
	return e
}

// ByAes decrypts by aes.
func (d Decrypter) ByAes(c *cipher.AesCipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return aes.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = aes.NewStdDecrypter(c).Decrypt(d.src)
	}

	return d
}

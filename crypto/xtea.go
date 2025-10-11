package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/xtea"
)

// ByXtea encrypts by xtea.
func (e Encrypter) ByXtea(c *cipher.XteaCipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return xtea.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = xtea.NewStdEncrypter(c).Encrypt(e.src)
	}

	return e
}

// ByXtea decrypts by xtea.
func (d Decrypter) ByXtea(c *cipher.XteaCipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return xtea.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = xtea.NewStdDecrypter(c).Decrypt(d.src)
	}

	return d
}

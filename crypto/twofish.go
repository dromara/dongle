package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/twofish"
)

// ByTwofish encrypts by twofish.
func (e Encrypter) ByTwofish(c *cipher.TwofishCipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return twofish.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = twofish.NewStdEncrypter(c).Encrypt(e.src)
	}
	return e
}

// ByTwofish decrypts by twofish.
func (d Decrypter) ByTwofish(c *cipher.TwofishCipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return twofish.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = twofish.NewStdDecrypter(c).Decrypt(d.src)
	}
	return d
}

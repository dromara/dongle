package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/blowfish"
	"github.com/dromara/dongle/crypto/cipher"
)

// ByBlowfish encrypts by blowfish
func (e Encrypter) ByBlowfish(c *cipher.BlowfishCipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return blowfish.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = blowfish.NewStdEncrypter(c).Encrypt(e.src)
	}
	return e
}

// ByBlowfish decrypts by blowfish
func (d Decrypter) ByBlowfish(c *cipher.BlowfishCipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return blowfish.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = blowfish.NewStdDecrypter(c).Decrypt(d.src)
	}

	return d
}

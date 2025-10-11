package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/chacha20"
	"github.com/dromara/dongle/crypto/cipher"
)

// ByChaCha20 encrypts by chacha20.
func (e Encrypter) ByChaCha20(c *cipher.ChaCha20Cipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return chacha20.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = chacha20.NewStdEncrypter(c).Encrypt(e.src)
	}

	return e
}

// ByChaCha20 decrypts by chacha20.
func (d Decrypter) ByChaCha20(c *cipher.ChaCha20Cipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return chacha20.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = chacha20.NewStdDecrypter(c).Decrypt(d.src)
	}

	return d
}

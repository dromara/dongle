package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/chacha20poly1305"
	"github.com/dromara/dongle/crypto/cipher"
)

// ByChaCha20Poly1305 encrypts by ChaCha20-Poly1305.
func (e *Encrypter) ByChaCha20Poly1305(c *cipher.ChaCha20Poly1305Cipher) *Encrypter {
	if e.Error != nil {
		return e
	}

	// If reader is set, use streaming processing
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return chacha20poly1305.NewStreamEncrypter(w, c)
		})
		return e
	}

	if len(e.src) > 0 {
		e.dst, e.Error = chacha20poly1305.NewStdEncrypter(c).Encrypt(e.src)
	}
	return e
}

// ByChaCha20Poly1305 decrypts by ChaCha20-Poly1305.
func (d *Decrypter) ByChaCha20Poly1305(c *cipher.ChaCha20Poly1305Cipher) *Decrypter {
	if d.Error != nil {
		return d
	}

	// If reader is set, use streaming processing
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return chacha20poly1305.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Decrypt data in memory
	if len(d.src) > 0 {
		d.dst, d.Error = chacha20poly1305.NewStdDecrypter(c).Decrypt(d.src)
	}
	return d
}

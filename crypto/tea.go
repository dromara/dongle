package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/tea"
)

// ByTea encrypts by TEA.
func (e *Encrypter) ByTea(c cipher.TeaCipher) *Encrypter {
	if e.Error != nil {
		return e
	}

	// If reader is set, use streaming processing
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return tea.NewStreamEncrypter(w, c)
		})
		return e
	}

	if len(e.src) > 0 {
		e.dst, e.Error = tea.NewStdEncrypter(c).Encrypt(e.src)
	}
	return e
}

// ByTea decrypts by TEA.
func (d *Decrypter) ByTea(c cipher.TeaCipher) *Decrypter {
	if d.Error != nil {
		return d
	}

	// If reader is set, use streaming processing
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return tea.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Decrypt data in memory
	if len(d.src) > 0 {
		d.dst, d.Error = tea.NewStdDecrypter(c).Decrypt(d.src)
	}
	return d
}

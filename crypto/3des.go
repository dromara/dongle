package crypto

import (
	"io"

	tripledes "github.com/dromara/dongle/crypto/3des"
	"github.com/dromara/dongle/crypto/cipher"
)

func (e Encrypter) By3Des(c *cipher.TripleDesCipher) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return tripledes.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = tripledes.NewStdEncrypter(c).Encrypt(e.src)
	}

	return e
}

func (d Decrypter) By3Des(c *cipher.TripleDesCipher) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return tripledes.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = tripledes.NewStdDecrypter(c).Decrypt(d.src)
	}

	return d
}

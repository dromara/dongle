package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/crypto/sm2"
)

// BySm2 encrypts by SM2.
func (e Encrypter) BySm2(kp *keypair.Sm2KeyPair) Encrypter {
	if e.Error != nil {
		return e
	}
	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return sm2.NewStreamEncrypter(w, kp)
		})
		return e
	}
	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = sm2.NewStdEncrypter(kp).Encrypt(e.src)
	}
	return e
}

// BySm2 decrypts by SM2.
func (d Decrypter) BySm2(kp *keypair.Sm2KeyPair) Decrypter {
	if d.Error != nil {
		return d
	}
	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return sm2.NewStreamDecrypter(r, kp)
		})
		return d
	}
	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = sm2.NewStdDecrypter(kp).Decrypt(d.src)
	}
	return d
}

package crypto

import (
	"io"

	triple_des "gitee.com/golang-package/dongle/crypto/3des"
	"gitee.com/golang-package/dongle/crypto/cipher"
)

func (e *Encrypter) By3Des(c cipher.TripleDesCipher) *Encrypter {
	if e.Error != nil {
		return e
	}

	// Check if we have a reader (streaming mode)
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return triple_des.NewStreamEncrypter(w, c)
		})
		return e
	}

	// Standard encryption mode
	enc := triple_des.NewStdEncrypter(c)
	if enc.Error != nil {
		e.Error = enc.Error
		return e
	}

	encrypted, err := enc.Encrypt(e.src)
	if err != nil {
		e.Error = err
		return e
	}

	e.dst = encrypted
	return e
}

func (d *Decrypter) By3Des(c cipher.TripleDesCipher) *Decrypter {
	if d.Error != nil {
		return d
	}

	// Check if we have a reader (streaming mode)
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return triple_des.NewStreamDecrypter(r, c)
		})
		return d
	}

	// Standard decryption mode
	decrypted, err := triple_des.NewStdDecrypter(c).Decrypt(d.src)
	if err != nil {
		d.Error = err
		return d
	}

	d.dst = decrypted
	return d
}

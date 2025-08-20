package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/crypto/rsa"
)

func (e *Encrypter) ByRsa(kp *keypair.RsaKeyPair) *Encrypter {
	if e.Error != nil {
		return e
	}

	// Check if we have a reader (streaming mode)
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return rsa.NewStreamEncrypter(w, kp)
		})
		return e
	}

	// Standard encryption mode
	encrypted, err := rsa.NewStdEncrypter(kp).Encrypt(e.src)
	if err != nil {
		e.Error = err
		return e
	}

	e.dst = encrypted
	return e
}

func (d *Decrypter) ByRsa(kp *keypair.RsaKeyPair) *Decrypter {
	if d.Error != nil {
		return d
	}

	// Check if we have a reader (streaming mode)
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return rsa.NewStreamDecrypter(r, kp)
		})
		return d
	}

	// Standard decryption mode
	decrypted, err := rsa.NewStdDecrypter(kp).Decrypt(d.src)
	if err != nil {
		d.Error = err
		return d
	}

	d.dst = decrypted
	return d
}

// ByRsa signs the data using RSA digital signature
func (s *Signer) ByRsa(kp *keypair.RsaKeyPair) *Signer {
	if s.Error != nil {
		return s
	}

	// Check if we have a reader (streaming mode)
	if s.reader != nil {
		s.sign, s.Error = s.stream(func(w io.Writer) io.WriteCloser {
			return rsa.NewStreamSigner(w, kp)
		})
		return s
	}

	// Standard signing mode
	signed, err := rsa.NewStdSigner(kp).Sign(s.src)
	if err != nil {
		s.Error = err
		return s
	}

	s.sign = signed
	return s
}

// ByRsa verifies the signature using RSA digital signature verification
func (v *Verifier) ByRsa(kp *keypair.RsaKeyPair) *Verifier {
	if v.Error != nil {
		return v
	}
	v.sign = kp.Sign

	// Check if we have a reader (streaming mode)
	if v.reader != nil {
		// For streaming verification, we need to provide the data to verify against
		// This is a simplified implementation that reads all data first
		_, err := v.stream(func(r io.Reader) io.Reader {
			return rsa.NewStreamVerifier(r, kp, v.src)
		})
		if err != nil {
			v.Error = err
		}
		return v
	}

	// Standard verification mode
	valid, err := rsa.NewStdVerifier(kp).Verify(v.src, v.sign)
	if err != nil {
		v.Error = err
		return v
	}

	if valid {
		v.src = []byte{1} // true
	}
	return v
}

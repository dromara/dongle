package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/crypto/rsa"
)

// ByRsa encrypts by rsa.
func (e Encrypter) ByRsa(kp *keypair.RsaKeyPair) Encrypter {
	if e.Error != nil {
		return e
	}

	// Streaming encryption mode
	if e.reader != nil {
		e.dst, e.Error = e.stream(func(w io.Writer) io.WriteCloser {
			return rsa.NewStreamEncrypter(w, kp)
		})
		return e
	}

	// Standard encryption mode
	if len(e.src) > 0 {
		e.dst, e.Error = rsa.NewStdEncrypter(kp).Encrypt(e.src)
	}

	return e
}

// ByRsa decrypts by rsa.
func (d Decrypter) ByRsa(kp *keypair.RsaKeyPair) Decrypter {
	if d.Error != nil {
		return d
	}

	// Streaming decryption mode
	if d.reader != nil {
		d.dst, d.Error = d.stream(func(r io.Reader) io.Reader {
			return rsa.NewStreamDecrypter(r, kp)
		})
		return d
	}

	// Standard decryption mode
	if len(d.src) > 0 {
		d.dst, d.Error = rsa.NewStdDecrypter(kp).Decrypt(d.src)
	}

	return d
}

// ByRsa signs by rsa.
func (s Signer) ByRsa(kp *keypair.RsaKeyPair) Signer {
	if s.Error != nil {
		return s
	}

	// Streaming signing mode
	if s.reader != nil {
		s.sign, s.Error = s.stream(func(w io.Writer) io.WriteCloser {
			return rsa.NewStreamSigner(w, kp)
		})
		return s
	}

	// Standard signing mode
	if len(s.data) > 0 {
		s.sign, s.Error = rsa.NewStdSigner(kp).Sign(s.data)
	}

	return s
}

// ByRsa verifies by rsa.
func (v Verifier) ByRsa(kp *keypair.RsaKeyPair) Verifier {
	if v.Error != nil {
		return v
	}

	// Streaming verification mode
	if v.reader != nil {
		verifier := rsa.NewStreamVerifier(v.reader, kp)

		// Write the data to be verified
		if len(v.data) > 0 {
			_, v.Error = verifier.Write(v.data)
		}

		// Close the verifier to perform verification
		v.Error = verifier.Close()
		if v.Error != nil {
			return v
		}

		// Set verification result
		v.data = []byte{1} // true
		return v
	}

	// Standard verification mode
	if len(v.data) > 0 {
		signature := v.sign
		if len(signature) == 0 {
			v.Error = &rsa.NoSignatureError{}
			return v
		}

		valid, err := rsa.NewStdVerifier(kp).Verify(v.data, signature)
		if err != nil {
			v.Error = err
			return v
		}
		if valid {
			v.data = []byte{1} // true
		}
	}

	return v
}

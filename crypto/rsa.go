package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/crypto/rsa"
)

func (e Encrypter) ByRsa(kp *keypair.RsaKeyPair) Encrypter {
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

func (d Decrypter) ByRsa(kp *keypair.RsaKeyPair) Decrypter {
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
func (s Signer) ByRsa(kp *keypair.RsaKeyPair) Signer {
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
	signed, err := rsa.NewStdSigner(kp).Sign(s.data)
	if err != nil {
		s.Error = err
		return s
	}

	s.sign = signed
	return s
}

// ByRsa verifies the signature using RSA digital signature verification
func (v Verifier) ByRsa(kp *keypair.RsaKeyPair) Verifier {
	if v.Error != nil {
		return v
	}

	if v.reader != nil {
		// For streaming verification, we need to process the data through the verifier
		// Since NewStreamVerifier now returns io.WriteCloser, we need to handle this differently
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

	signature := kp.Sign
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
		v.sign = signature // Set the signature for ToBool() to work
	}
	return v
}

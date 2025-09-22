package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/ed25519"
	"github.com/dromara/dongle/crypto/keypair"
)

// ByEd25519 signs the data using ED25519 digital signature
func (s Signer) ByEd25519(kp *keypair.Ed25519KeyPair) Signer {
	if s.Error != nil {
		return s
	}

	if kp == nil {
		s.Error = &ed25519.NilKeyPairError{}
		return s
	}

	// Check if we have a reader (streaming mode)
	if s.reader != nil {
		s.sign, s.Error = s.stream(func(w io.Writer) io.WriteCloser {
			return ed25519.NewStreamSigner(w, kp)
		})
		return s
	}

	// Standard signing mode
	signed, err := ed25519.NewStdSigner(kp).Sign(s.data)
	if err != nil {
		s.Error = err
		return s
	}

	s.sign = signed
	return s
}

// ByEd25519 verifies the signature using ED25519 digital signature verification
func (v Verifier) ByEd25519(kp *keypair.Ed25519KeyPair) Verifier {
	if v.Error != nil {
		return v
	}

	if kp == nil {
		v.Error = &ed25519.NilKeyPairError{}
		return v
	}

	if v.reader != nil {
		// For streaming verification, we need to process the data through the verifier
		// In streaming mode, the signature should be in kp.Sign
		signature := kp.Sign
		if len(signature) == 0 {
			v.Error = &ed25519.NoSignatureError{}
			return v
		}

		// Create a stream verifier
		streamVerifier := ed25519.NewStreamVerifier(v.reader, kp)
		defer streamVerifier.Close()

		// Write data to the stream verifier
		if len(v.data) > 0 {
			_, v.Error = streamVerifier.Write(v.data)
			if v.Error != nil {
				return v
			}
		}

		// Set verification result
		v.data = []byte{1} // true
		return v
	}

	signature := kp.Sign
	if len(signature) == 0 {
		v.Error = &ed25519.NoSignatureError{}
		return v
	}

	valid, err := ed25519.NewStdVerifier(kp).Verify(v.data, signature)
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

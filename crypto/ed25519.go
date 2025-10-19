package crypto

import (
	"io"

	"github.com/dromara/dongle/crypto/ed25519"
	"github.com/dromara/dongle/crypto/keypair"
)

// ByEd25519 signs by ed25519.
func (s Signer) ByEd25519(kp *keypair.Ed25519KeyPair) Signer {
	if s.Error != nil {
		return s
	}

	// Streaming signing mode
	if s.reader != nil {
		s.sign, s.Error = s.stream(func(w io.Writer) io.WriteCloser {
			return ed25519.NewStreamSigner(w, kp)
		})
		return s
	}

	// Standard signing mode
	if len(s.data) > 0 {
		s.sign, s.Error = ed25519.NewStdSigner(kp).Sign(s.data)
	}

	return s
}

// ByEd25519 verifies by ed25519.
func (v Verifier) ByEd25519(kp *keypair.Ed25519KeyPair) Verifier {
	if v.Error != nil {
		return v
	}

	// Streaming verification mode
	if v.reader != nil {
		signature := v.sign
		if len(signature) == 0 {
			v.Error = &ed25519.NoSignatureError{}
			return v
		}

		// Create a stream verifier
		verifier := ed25519.NewStreamVerifier(v.reader, kp)
		defer verifier.Close()

		// Write data to the stream verifier
		if len(v.data) > 0 {
			_, v.Error = verifier.Write(v.data)
		}

		// Close the verifier to perform verification
		v.Error = verifier.Close()
		if v.Error != nil {
			return v
		}

		v.verify = true
		return v
	}

	// Standard verification mode
	if len(v.data) > 0 {
		signature := v.sign
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
			v.verify = true
		}
	}

	return v
}

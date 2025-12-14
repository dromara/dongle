package rsa

import (
	"io"

	"github.com/dromara/dongle/crypto/internal/rsa"
	"github.com/dromara/dongle/crypto/keypair"
)

type StdVerifier struct {
	keypair keypair.RsaKeyPair // The key pair containing public key and format
	cache   cache              // Cached keys and hash for better performance
	Error   error              // Error field for storing verification errors
}

func NewStdVerifier(kp *keypair.RsaKeyPair) *StdVerifier {
	v := &StdVerifier{
		keypair: *kp,
	}
	if v.keypair.Type == "" {
		v.keypair.Type = keypair.PublicKey
	}
	if v.keypair.Type == keypair.PublicKey {
		if len(v.keypair.PublicKey) == 0 {
			v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
			return v
		}
		pubKey, err := v.keypair.ParsePublicKey()
		if err != nil {
			v.Error = VerifyError{Err: err}
			return v
		}
		v.cache.pubKey = pubKey
	}

	if v.keypair.Format == keypair.PKCS1 && v.keypair.Padding == "" {
		v.keypair.Padding = keypair.PKCS1v15
	}
	if v.keypair.Format == keypair.PKCS8 && v.keypair.Padding == "" {
		v.keypair.Padding = keypair.PSS
	}
	if v.keypair.Padding == "" {
		v.Error = VerifyError{Err: keypair.EmptyPaddingError{}}
		return v
	}
	if v.keypair.Padding == keypair.OAEP {
		v.Error = VerifyError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(v.keypair.Padding)}}
		return v
	}
	v.cache.hash = kp.Hash.New()
	return v
}

func (v *StdVerifier) Verify(src, sign []byte) (valid bool, err error) {
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(src) == 0 {
		return
	}
	if len(sign) == 0 {
		err = VerifyError{Err: keypair.EmptySignatureError{}}
		return
	}
	hasher := v.cache.hash
	hasher.Reset()
	hasher.Write(src)
	hashed := hasher.Sum(nil)
	switch v.keypair.Padding {
	case keypair.PKCS1v15:
		err = rsa.VerifyPKCS1v15WithPublicKey(v.cache.pubKey, v.keypair.Hash, hashed, sign)
	case keypair.PSS:
		err = rsa.VerifyPSSWithPublicKey(v.cache.pubKey, v.keypair.Hash, hashed, sign)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(v.keypair.Padding)}
	}
	if err != nil {
		err = VerifyError{Err: err}
		return
	}
	return true, nil
}

type StreamVerifier struct {
	keypair   keypair.RsaKeyPair // Key pair containing padding and hash configuration
	cache     cache              // Cached keys and hash for better performance
	reader    io.Reader          // Underlying reader for data input
	signature []byte             // Signature to verify
	verified  bool               // Whether verification has been performed
	Error     error              // Error field for storing verification errors
}

func NewStreamVerifier(r io.Reader, kp *keypair.RsaKeyPair) io.WriteCloser {
	v := &StreamVerifier{
		keypair: *kp,
		reader:  r,
	}
	if v.keypair.Type == "" {
		v.keypair.Type = keypair.PublicKey
	}
	if v.keypair.Type == keypair.PublicKey {
		if len(v.keypair.PublicKey) == 0 {
			v.Error = VerifyError{Err: keypair.EmptyPublicKeyError{}}
			return v
		}
		pubKey, err := v.keypair.ParsePublicKey()
		if err != nil {
			v.Error = VerifyError{Err: err}
			return v
		}
		v.cache.pubKey = pubKey
	}

	if v.keypair.Type == keypair.PrivateKey {
		if len(v.keypair.PrivateKey) == 0 {
			v.Error = VerifyError{Err: keypair.EmptyPrivateKeyError{}}
			return v
		}
		priKey, err := v.keypair.ParsePrivateKey()
		if err != nil {
			v.Error = VerifyError{Err: err}
			return v
		}
		v.cache.priKey = priKey
	}

	if v.keypair.Format == keypair.PKCS1 && v.keypair.Padding == "" {
		v.keypair.Padding = keypair.PKCS1v15
	}
	if v.keypair.Format == keypair.PKCS8 && v.keypair.Padding == "" {
		v.keypair.Padding = keypair.PSS
	}
	if v.keypair.Padding == "" {
		v.Error = VerifyError{Err: keypair.EmptyPaddingError{}}
		return v
	}
	if v.keypair.Padding == keypair.OAEP {
		v.Error = VerifyError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(v.keypair.Padding)}}
		return v
	}
	v.cache.hash = kp.Hash.New()
	return v
}

func (v *StreamVerifier) verify(hashed, signature []byte) (valid bool, err error) {
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(hashed) == 0 {
		return
	}
	switch {
	case v.keypair.Type == keypair.PublicKey && v.keypair.Padding == keypair.PKCS1v15:
		err = rsa.VerifyPKCS1v15WithPublicKey(v.cache.pubKey, v.keypair.Hash, hashed, signature)
	case v.keypair.Type == keypair.PublicKey && v.keypair.Padding == keypair.PSS:
		err = rsa.VerifyPSSWithPublicKey(v.cache.pubKey, v.keypair.Hash, hashed, signature)
	case v.keypair.Type == keypair.PrivateKey && v.keypair.Padding == keypair.PKCS1v15:
		err = rsa.VerifyPKCS1v15WithPrivateKey(v.cache.priKey, v.keypair.Hash, hashed, signature)
	case v.keypair.Type == keypair.PrivateKey && v.keypair.Padding == keypair.PSS:
		err = rsa.VerifyPSSWithPrivateKey(v.cache.priKey, v.keypair.Hash, hashed, signature)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(v.keypair.Padding)}
	}
	if err != nil {
		err = VerifyError{Err: err}
		return
	}
	return true, nil
}

// Write processes data through the hash function for streaming verification
func (v *StreamVerifier) Write(p []byte) (n int, err error) {
	if v.Error != nil {
		err = v.Error
		return
	}
	if len(p) == 0 {
		return
	}
	// Process data through the hash function for streaming
	v.cache.hash.Write(p)
	return len(p), nil
}

// Close performs the final verification and closes the verifier
func (v *StreamVerifier) Close() error {
	if v.Error != nil {
		return v.Error
	}
	// Read signature data from the underlying reader
	var err error
	v.signature, err = io.ReadAll(v.reader)
	if err != nil {
		return ReadError{Err: err}
	}
	if len(v.signature) == 0 {
		return nil
	}
	// Get the final hash sum from the hash
	hashed := v.cache.hash.Sum(nil)
	// Verify the signature using the hashed data
	if _, err = v.verify(hashed, v.signature); err != nil {
		return err
	}
	// Mark verification as completed
	v.verified = true
	// Close the underlying reader if it implements io.Closer
	if closer, ok := v.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

package rsa

import (
	"crypto/rand"
	"io"

	"github.com/dromara/dongle/crypto/internal/rsa"
	"github.com/dromara/dongle/crypto/keypair"
)

type StdSigner struct {
	keypair keypair.RsaKeyPair // The key pair containing private key and format
	cache   cache              // Cached keys and hash for better performance
	Error   error              // Error field for storing signature errors
}

func NewStdSigner(kp *keypair.RsaKeyPair) *StdSigner {
	s := &StdSigner{
		keypair: *kp,
	}
	if s.keypair.Type == "" {
		s.keypair.Type = keypair.PrivateKey
	}
	if s.keypair.Type == keypair.PublicKey {
		if len(s.keypair.PublicKey) == 0 {
			s.Error = SignError{Err: keypair.EmptyPublicKeyError{}}
			return s
		}
		pubKey, err := s.keypair.ParsePublicKey()
		if err != nil {
			s.Error = SignError{Err: err}
			return s
		}
		s.cache.pubKey = pubKey
	}

	if s.keypair.Type == keypair.PrivateKey {
		if len(s.keypair.PrivateKey) == 0 {
			s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
			return s
		}
		priKey, err := s.keypair.ParsePrivateKey()
		if err != nil {
			s.Error = SignError{Err: err}
			return s
		}
		s.cache.priKey = priKey
	}

	if s.keypair.Format == keypair.PKCS1 && s.keypair.Padding == "" {
		s.keypair.Padding = keypair.PKCS1v15
	}
	if s.keypair.Format == keypair.PKCS8 && s.keypair.Padding == "" {
		s.keypair.Padding = keypair.PSS
	}
	if s.keypair.Padding == "" {
		s.Error = SignError{Err: keypair.EmptyPaddingError{}}
		return s
	}
	if s.keypair.Padding == keypair.OAEP {
		s.Error = SignError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(s.keypair.Padding)}}
		return s
	}
	s.cache.hash = kp.Hash.New()
	return s
}

func (s *StdSigner) Sign(src []byte) (sign []byte, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(src) == 0 {
		return
	}
	hasher := s.keypair.Hash.New()
	hasher.Write(src)
	hashed := hasher.Sum(nil)
	switch {
	case s.keypair.Type == keypair.PublicKey && s.keypair.Padding == keypair.PKCS1v15:
		sign, err = rsa.SignPKCS1v15WithPublicKey(s.cache.pubKey, s.keypair.Hash, hashed)
	case s.keypair.Type == keypair.PublicKey && s.keypair.Padding == keypair.PSS:
		sign, err = rsa.SignPSSWithPublicKey(rand.Reader, s.cache.pubKey, s.keypair.Hash, hashed)
	case s.keypair.Type == keypair.PrivateKey && s.keypair.Padding == keypair.PKCS1v15:
		sign, err = rsa.SignPKCS1v15WithPrivateKey(rand.Reader, s.cache.priKey, s.keypair.Hash, hashed)
	case s.keypair.Type == keypair.PrivateKey && s.keypair.Padding == keypair.PSS:
		sign, err = rsa.SignPSSWithPrivateKey(rand.Reader, s.cache.priKey, s.keypair.Hash, hashed)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(s.keypair.Padding)}
	}
	if err != nil {
		err = SignError{Err: err}
		return
	}
	return
}

type StreamSigner struct {
	keypair keypair.RsaKeyPair // Key pair containing padding and hash configuration
	cache   cache              // Cached keys and hash for better performance
	writer  io.Writer          // Underlying writer for signature output
	Error   error              // Error field for storing signature errors
}

func NewStreamSigner(w io.Writer, kp *keypair.RsaKeyPair) io.WriteCloser {
	s := &StreamSigner{
		keypair: *kp,
		writer:  w,
	}
	if s.keypair.Type == "" {
		s.keypair.Type = keypair.PrivateKey
	}
	if s.keypair.Type == keypair.PublicKey {
		if len(s.keypair.PublicKey) == 0 {
			s.Error = SignError{Err: keypair.EmptyPublicKeyError{}}
			return s
		}
		pubKey, err := s.keypair.ParsePublicKey()
		if err != nil {
			s.Error = SignError{Err: err}
			return s
		}
		s.cache.pubKey = pubKey
	}

	if s.keypair.Type == keypair.PrivateKey {
		if len(s.keypair.PrivateKey) == 0 {
			s.Error = SignError{Err: keypair.EmptyPrivateKeyError{}}
			return s
		}
		priKey, err := s.keypair.ParsePrivateKey()
		if err != nil {
			s.Error = SignError{Err: err}
			return s
		}
		s.cache.priKey = priKey
	}

	if s.keypair.Format == keypair.PKCS1 && s.keypair.Padding == "" {
		s.keypair.Padding = keypair.PKCS1v15
	}
	if s.keypair.Format == keypair.PKCS8 && s.keypair.Padding == "" {
		s.keypair.Padding = keypair.PSS
	}
	if s.keypair.Padding == "" {
		s.Error = SignError{Err: keypair.EmptyPaddingError{}}
		return s
	}
	if s.keypair.Padding == keypair.OAEP {
		s.Error = SignError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(s.keypair.Padding)}}
		return s
	}
	s.cache.hash = kp.Hash.New()
	return s
}

func (s *StreamSigner) sign(data []byte) (dst []byte, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(data) == 0 {
		return
	}
	switch {
	case s.keypair.Type == keypair.PublicKey && s.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.SignPKCS1v15WithPublicKey(s.cache.pubKey, s.keypair.Hash, data)
	case s.keypair.Type == keypair.PublicKey && s.keypair.Padding == keypair.PSS:
		dst, err = rsa.SignPSSWithPublicKey(rand.Reader, s.cache.pubKey, s.keypair.Hash, data)
	case s.keypair.Type == keypair.PrivateKey && s.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.SignPKCS1v15WithPrivateKey(rand.Reader, s.cache.priKey, s.keypair.Hash, data)
	case s.keypair.Type == keypair.PrivateKey && s.keypair.Padding == keypair.PSS:
		dst, err = rsa.SignPSSWithPrivateKey(rand.Reader, s.cache.priKey, s.keypair.Hash, data)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(s.keypair.Padding)}
	}
	if err != nil {
		err = SignError{Err: err}
		return
	}
	return
}

func (s *StreamSigner) Write(p []byte) (n int, err error) {
	if s.Error != nil {
		err = s.Error
		return
	}
	if len(p) == 0 {
		return
	}
	s.cache.hash.Write(p)
	return len(p), nil
}

func (s *StreamSigner) Close() error {
	if s.Error != nil {
		return s.Error
	}
	// Get the final hash sum from the hash
	hashed := s.cache.hash.Sum(nil)
	// Generate signature for the hashed data
	dst, signErr := s.sign(hashed)
	if signErr != nil {
		return signErr
	}
	// Write signature to the underlying writer
	if _, WriteErr := s.writer.Write(dst); WriteErr != nil {
		return WriteErr
	}
	// Close the underlying writer if it implements io.Closer
	if closer, ok := s.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

package rsa

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/dromara/dongle/crypto/internal/rsa"
	"github.com/dromara/dongle/crypto/keypair"
)

type StdDecrypter struct {
	keypair keypair.RsaKeyPair // The key pair containing private key and format
	cache   cache              // Cached keys and hash for better performance
	Error   error              // Error field for storing decryption errors
}

func NewStdDecrypter(kp *keypair.RsaKeyPair) *StdDecrypter {
	d := &StdDecrypter{
		keypair: *kp,
	}
	if d.keypair.Type == "" {
		d.keypair.Type = keypair.PrivateKey
	}
	if d.keypair.Type == keypair.PublicKey {
		if len(d.keypair.PublicKey) == 0 {
			d.Error = DecryptError{Err: keypair.EmptyPublicKeyError{}}
			return d
		}
		pubKey, err := d.keypair.ParsePublicKey()
		if err != nil {
			d.Error = DecryptError{Err: err}
			return d
		}
		d.cache.pubKey = pubKey
	}

	if d.keypair.Type == keypair.PrivateKey {
		if len(d.keypair.PrivateKey) == 0 {
			d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
			return d
		}
		priKey, err := d.keypair.ParsePrivateKey()
		if err != nil {
			d.Error = DecryptError{Err: err}
			return d
		}
		d.cache.priKey = priKey
	}

	if d.keypair.Format == keypair.PKCS1 && d.keypair.Padding == "" {
		d.keypair.Padding = keypair.PKCS1v15
	}
	if d.keypair.Format == keypair.PKCS8 && d.keypair.Padding == "" {
		d.keypair.Padding = keypair.OAEP
	}
	if d.keypair.Padding == "" {
		d.Error = DecryptError{Err: keypair.EmptyPaddingError{}}
		return d
	}
	if d.keypair.Padding == keypair.OAEP {
		d.cache.hash = kp.Hash.New()
	}
	if d.keypair.Padding == keypair.PSS {
		d.Error = DecryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(d.keypair.Padding)}}
		return d
	}
	return d
}

func (d *StdDecrypter) Decrypt(src []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	if len(src) == 0 {
		return
	}
	switch {
	case d.keypair.Type == keypair.PublicKey && d.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.DecryptPKCS1v15WithPublicKey(d.cache.pubKey, src)
	case d.keypair.Type == keypair.PublicKey && d.keypair.Padding == keypair.OAEP:
		dst, err = rsa.DecryptOAEPWithPublicKey(d.cache.hash, d.cache.pubKey, src)
	case d.keypair.Type == keypair.PrivateKey && d.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.DecryptPKCS1v15WithPrivateKey(rand.Reader, d.cache.priKey, src)
	case d.keypair.Type == keypair.PrivateKey && d.keypair.Padding == keypair.OAEP:
		dst, err = rsa.DecryptOAEPWithPrivateKey(d.cache.hash, rand.Reader, d.cache.priKey, src)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(d.keypair.Padding)}
	}
	if err != nil {
		err = DecryptError{Err: err}
		return
	}
	return
}

type StreamDecrypter struct {
	keypair  keypair.RsaKeyPair // Key pair containing padding and hash configuration
	cache    cache              // Cached keys and hash for better performance
	reader   io.Reader          // Underlying reader for encrypted input
	buffer   []byte             // Buffer for decrypted data
	position int                // Current position in buffer
	Error    error              // Error field for storing decryption errors
}

func NewStreamDecrypter(r io.Reader, kp *keypair.RsaKeyPair) io.Reader {
	d := &StreamDecrypter{
		keypair:  *kp,
		reader:   r,
		position: 0,
	}
	if d.keypair.Type == "" {
		d.keypair.Type = keypair.PrivateKey
	}
	if d.keypair.Type == keypair.PublicKey {
		if len(d.keypair.PublicKey) == 0 {
			d.Error = DecryptError{Err: keypair.EmptyPublicKeyError{}}
			return d
		}
		pubKey, err := d.keypair.ParsePublicKey()
		if err != nil {
			d.Error = DecryptError{Err: err}
			return d
		}
		d.cache.pubKey = pubKey
	}

	if d.keypair.Type == keypair.PrivateKey {
		if len(d.keypair.PrivateKey) == 0 {
			d.Error = DecryptError{Err: keypair.EmptyPrivateKeyError{}}
			return d
		}
		priKey, err := d.keypair.ParsePrivateKey()
		if err != nil {
			d.Error = DecryptError{Err: err}
			return d
		}
		d.cache.priKey = priKey
	}

	if d.keypair.Format == keypair.PKCS1 && d.keypair.Padding == "" {
		d.keypair.Padding = keypair.PKCS1v15
	}
	if d.keypair.Format == keypair.PKCS8 && d.keypair.Padding == "" {
		d.keypair.Padding = keypair.OAEP
	}
	if d.keypair.Padding == "" {
		d.Error = DecryptError{Err: keypair.EmptyPaddingError{}}
		return d
	}
	if d.keypair.Padding == keypair.OAEP {
		d.cache.hash = kp.Hash.New()
	}
	if d.keypair.Padding == keypair.PSS {
		d.Error = DecryptError{Err: keypair.UnsupportedPaddingSchemeError{Padding: string(d.keypair.Padding)}}
		return d
	}

	return d
}

func (d *StreamDecrypter) decrypt(data []byte) (dst []byte, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	if len(data) == 0 {
		return
	}
	switch {
	case d.keypair.Type == keypair.PublicKey && d.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.DecryptPKCS1v15WithPublicKey(d.cache.pubKey, data)
	case d.keypair.Type == keypair.PublicKey && d.keypair.Padding == keypair.OAEP:
		dst, err = rsa.DecryptOAEPWithPublicKey(d.cache.hash, d.cache.pubKey, data)
	case d.keypair.Type == keypair.PrivateKey && d.keypair.Padding == keypair.PKCS1v15:
		dst, err = rsa.DecryptPKCS1v15WithPrivateKey(rand.Reader, d.cache.priKey, data)
	case d.keypair.Type == keypair.PrivateKey && d.keypair.Padding == keypair.OAEP:
		dst, err = rsa.DecryptOAEPWithPrivateKey(d.cache.hash, rand.Reader, d.cache.priKey, data)
	default:
		err = keypair.UnsupportedPaddingSchemeError{Padding: string(d.keypair.Padding)}
	}
	if err != nil {
		err = DecryptError{Err: err}
		return
	}
	return
}

func (d *StreamDecrypter) Read(p []byte) (n int, err error) {
	if d.Error != nil {
		err = d.Error
		return
	}
	// If we have decrypted data available, return it
	if d.position < len(d.buffer) {
		n = copy(p, d.buffer[d.position:])
		d.position += n
		return
	}

	// If we've exhausted all decrypted data, try to read more
	if d.position >= len(d.buffer) {
		// Determine block size based on key type
		var blockSize int
		if d.keypair.Type == keypair.PublicKey {
			blockSize = d.cache.pubKey.Size()
		}
		if d.keypair.Type == keypair.PrivateKey {
			blockSize = d.cache.priKey.Size()
		}

		// Read one encrypted block from the underlying reader
		encryptedBlock := make([]byte, blockSize)
		_, readErr := io.ReadFull(d.reader, encryptedBlock)

		if readErr == io.EOF || errors.Is(readErr, io.ErrUnexpectedEOF) {
			return 0, io.EOF
		}
		if readErr != nil {
			err = ReadError{Err: readErr}
			return
		}

		// Note: io.ReadFull guarantees bytesRead == blockSize when readErr == nil
		dst, decErr := d.decrypt(encryptedBlock)
		if decErr != nil {
			return 0, decErr
		}

		// Store decrypted data and reset position
		d.buffer = dst
		d.position = 0

		// Return decrypted data
		if len(d.buffer) > 0 {
			n = copy(p, d.buffer)
			d.position += n
			return
		}
	}
	return 0, io.EOF
}

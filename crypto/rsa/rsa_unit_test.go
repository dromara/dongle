package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	stdRSA "crypto/rsa"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustKeyPair(t *testing.T, format keypair.RsaKeyFormat) *keypair.RsaKeyPair {
	t.Helper()
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(format)
	kp.SetHash(crypto.SHA256)
	require.NoError(t, kp.GenKeyPair(1024))
	return kp
}

func TestNewStdEncrypterValidation(t *testing.T) {
	emptyKey := keypair.NewRsaKeyPair()
	emptyKey.SetFormat(keypair.PKCS1)
	enc := NewStdEncrypter(emptyKey)
	assert.IsType(t, EncryptError{}, enc.Error)

	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.PSS)
	errEncrypter := NewStdEncrypter(kp)
	assert.IsType(t, EncryptError{}, errEncrypter.Error)
}

func TestStdEncrypterEncrypt(t *testing.T) {
	t.Run("success pkcs1 default padding", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		enc := NewStdEncrypter(kp)
		dst, err := enc.Encrypt([]byte("hello"))
		require.NoError(t, err)
		assert.NotEmpty(t, dst)
	})

	t.Run("success oaep", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		enc := NewStdEncrypter(kp)
		dst, err := enc.Encrypt([]byte("oaep"))
		require.NoError(t, err)
		assert.NotEmpty(t, dst)
	})

	t.Run("existing error short circuits", func(t *testing.T) {
		enc := &StdEncrypter{Error: assert.AnError}
		dst, err := enc.Encrypt([]byte("ignored"))
		assert.Nil(t, dst)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("empty input returns nil", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		enc := NewStdEncrypter(kp)
		dst, err := enc.Encrypt(nil)
		assert.Nil(t, dst)
		assert.NoError(t, err)
	})

	t.Run("invalid public key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.PublicKey = []byte("bad-key")
		enc := NewStdEncrypter(kp)
		dst, err := enc.Encrypt([]byte("data"))
		assert.Nil(t, dst)
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, enc.Error)
	})

	t.Run("empty padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Format = ""
		kp.Padding = ""
		enc := NewStdEncrypter(kp)
		_, err := enc.Encrypt([]byte("data"))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, enc.Error)
	})

	t.Run("invalid padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Padding = keypair.RsaPaddingScheme("weird")
		enc := NewStdEncrypter(kp)
		_, err := enc.Encrypt([]byte("data"))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, enc.Error)
	})

	t.Run("encryption failure propagates", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		enc := NewStdEncrypter(kp)
		// make payload larger than modulus - 11 to trigger rsa error
		_, err := enc.Encrypt(bytes.Repeat([]byte("a"), 256))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, enc.Error)
	})
}

func TestNewStdDecrypterValidation(t *testing.T) {
	emptyKey := keypair.NewRsaKeyPair()
	emptyKey.SetFormat(keypair.PKCS1)
	dec := NewStdDecrypter(emptyKey)
	assert.IsType(t, DecryptError{}, dec.Error)

	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.PSS)
	errDec := NewStdDecrypter(kp)
	assert.IsType(t, DecryptError{}, errDec.Error)
}

func TestStdDecrypterDecrypt(t *testing.T) {
	t.Run("success pkcs1", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		enc := NewStdEncrypter(kp)
		cipher, err := enc.Encrypt([]byte("secret"))
		require.NoError(t, err)

		dec := NewStdDecrypter(kp)
		plain, derr := dec.Decrypt(cipher)
		require.NoError(t, derr)
		assert.Equal(t, "secret", string(plain))
	})

	t.Run("success oaep", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		enc := NewStdEncrypter(kp)
		cipher, err := enc.Encrypt([]byte("oaep"))
		require.NoError(t, err)

		dec := NewStdDecrypter(kp)
		plain, derr := dec.Decrypt(cipher)
		require.NoError(t, derr)
		assert.Equal(t, "oaep", string(plain))
	})

	t.Run("existing error short circuits", func(t *testing.T) {
		dec := &StdDecrypter{Error: assert.AnError}
		dst, err := dec.Decrypt([]byte("ignored"))
		assert.Nil(t, dst)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("empty input returns nil", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		dec := NewStdDecrypter(kp)
		dst, err := dec.Decrypt(nil)
		assert.Nil(t, dst)
		assert.NoError(t, err)
	})

	t.Run("invalid private key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.PrivateKey = []byte("bad-key")
		dec := NewStdDecrypter(kp)
		dst, err := dec.Decrypt([]byte("data"))
		assert.Nil(t, dst)
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, dec.Error)
	})

	t.Run("empty padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Format = ""
		kp.Padding = ""
		dec := NewStdDecrypter(kp)
		_, err := dec.Decrypt([]byte("cipher"))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, dec.Error)
	})

	t.Run("invalid padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Padding = keypair.RsaPaddingScheme("weird")
		dec := NewStdDecrypter(kp)
		_, err := dec.Decrypt([]byte("cipher"))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, dec.Error)
	})

	t.Run("decrypt failure propagates", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		dec := NewStdDecrypter(kp)
		_, err := dec.Decrypt([]byte("random cipher"))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, dec.Error)
	})
}

func TestStreamEncrypterNew(t *testing.T) {
	emptyKey := keypair.NewRsaKeyPair()
	emptyKey.SetFormat(keypair.PKCS1)
	se := NewStreamEncrypter(bytes.NewBuffer(nil), emptyKey).(*StreamEncrypter)
	assert.IsType(t, EncryptError{}, se.Error)

	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.PSS)
	pss := NewStreamEncrypter(bytes.NewBuffer(nil), kp).(*StreamEncrypter)
	assert.IsType(t, EncryptError{}, pss.Error)

	kp2 := keypair.NewRsaKeyPair()
	kp2.SetFormat(keypair.PKCS1)
	kp2.SetHash(crypto.SHA256)
	kp2.PublicKey = []byte("bad")
	bad := NewStreamEncrypter(bytes.NewBuffer(nil), kp2).(*StreamEncrypter)
	assert.IsType(t, EncryptError{}, bad.Error)

	kp3 := mustKeyPair(t, keypair.PKCS1)
	kp3.Padding = keypair.RsaPaddingScheme("weird")
	invalid := NewStreamEncrypter(bytes.NewBuffer(nil), kp3).(*StreamEncrypter)
	assert.IsType(t, EncryptError{}, invalid.Error)

	t.Run("oaep defaults applied", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		se := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		require.NoError(t, se.Error)
		assert.NotNil(t, se.hashFunc)
		expectedChunk := se.pubKey.Size() - 2*kp.Hash.Size() - 2
		assert.Equal(t, expectedChunk, se.chunkSize)
	})
}

func TestStreamEncrypterWriteCloseEncrypt(t *testing.T) {
	kp := mustKeyPair(t, keypair.PKCS1)
	buf := &bytes.Buffer{}
	w := mock.NewWriteCloser(buf)
	se := NewStreamEncrypter(w, kp).(*StreamEncrypter)
	require.NoError(t, se.Error)
	assert.Positive(t, se.chunkSize)

	payload := bytes.Repeat([]byte("a"), se.chunkSize+5)
	n, err := se.Write(payload)
	require.NoError(t, err)
	assert.Equal(t, len(payload), n)
	assert.Greater(t, buf.Len(), 0)

	// buffer should be flushed on close
	err = se.Close()
	require.NoError(t, err)

	t.Run("write with preset error", func(t *testing.T) {
		se := &StreamEncrypter{Error: assert.AnError}
		_, err := se.Write([]byte("data"))
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("write empty slice", func(t *testing.T) {
		se := NewStreamEncrypter(mock.NewWriteCloser(&bytes.Buffer{}), kp).(*StreamEncrypter)
		n, err := se.Write(nil)
		assert.Equal(t, 0, n)
		assert.NoError(t, err)
	})

	t.Run("writer error propagates", func(t *testing.T) {
		errWriter := mock.NewErrorWriteAfterN(0, assert.AnError)
		se := NewStreamEncrypter(errWriter, kp).(*StreamEncrypter)
		_, err := se.Write(bytes.Repeat([]byte("x"), se.chunkSize))
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close with buffered data and close error", func(t *testing.T) {
		w := mock.NewCloseErrorWriteCloser(&bytes.Buffer{}, assert.AnError)
		se := NewStreamEncrypter(w, kp).(*StreamEncrypter)
		_, err := se.Write([]byte("buffered"))
		require.NoError(t, err)
		assert.Equal(t, assert.AnError, se.Close())
	})

	t.Run("close with preset error", func(t *testing.T) {
		se := &StreamEncrypter{Error: assert.AnError}
		assert.Equal(t, assert.AnError, se.Close())
	})

	t.Run("close with empty buffer no closer", func(t *testing.T) {
		se := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		_, err := se.Write(bytes.Repeat([]byte("b"), se.chunkSize))
		require.NoError(t, err)
		assert.NoError(t, se.Close())
	})

	t.Run("write encryption error with invalid padding", func(t *testing.T) {
		se := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		se.keypair.Padding = ""
		_, err := se.Write(bytes.Repeat([]byte("x"), se.chunkSize))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("close encryption error with invalid padding", func(t *testing.T) {
		se := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		se.buffer = []byte("data")
		se.keypair.Padding = ""
		err := se.Close()
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("close write error", func(t *testing.T) {
		se := NewStreamEncrypter(mock.NewErrorWriteCloser(assert.AnError), kp).(*StreamEncrypter)
		se.buffer = []byte("data")
		se.pubKey, _ = kp.ParsePublicKey()
		assert.Equal(t, assert.AnError, se.Close())
	})

	t.Run("encrypt with invalid padding", func(t *testing.T) {
		se := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		se.keypair.Padding = keypair.RsaPaddingScheme("invalid")
		_, err := se.encrypt([]byte("data"))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encrypt with oaep", func(t *testing.T) {
		oaepKP := mustKeyPair(t, keypair.PKCS8)
		se := NewStreamEncrypter(&bytes.Buffer{}, oaepKP).(*StreamEncrypter)
		encrypted, err := se.encrypt([]byte("test"))
		assert.NoError(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("encrypt oversized data", func(t *testing.T) {
		se := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		_, err := se.encrypt(bytes.Repeat([]byte("a"), 256))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		se := NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
		encrypted, err := se.encrypt([]byte{})
		assert.NoError(t, err)
		assert.Empty(t, encrypted)
	})
}

func TestStreamDecrypterNew(t *testing.T) {
	emptyKey := keypair.NewRsaKeyPair()
	emptyKey.SetFormat(keypair.PKCS1)
	sd := NewStreamDecrypter(bytes.NewBuffer(nil), emptyKey).(*StreamDecrypter)
	assert.IsType(t, DecryptError{}, sd.Error)

	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.PSS)
	pss := NewStreamDecrypter(bytes.NewBuffer(nil), kp).(*StreamDecrypter)
	assert.IsType(t, DecryptError{}, pss.Error)

	kp2 := keypair.NewRsaKeyPair()
	kp2.SetFormat(keypair.PKCS1)
	kp2.SetHash(crypto.SHA256)
	kp2.PrivateKey = []byte("bad")
	bad := NewStreamDecrypter(bytes.NewBuffer(nil), kp2).(*StreamDecrypter)
	assert.IsType(t, DecryptError{}, bad.Error)

	t.Run("oaep defaults applied", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		sd := NewStreamDecrypter(bytes.NewBuffer(nil), kp).(*StreamDecrypter)
		require.NoError(t, sd.Error)
		assert.Equal(t, keypair.OAEP, sd.keypair.Padding)
		assert.NotNil(t, sd.hashFunc)
	})
}

func TestStreamDecrypterRead(t *testing.T) {
	kp := mustKeyPair(t, keypair.PKCS1)
	pub, _ := kp.ParsePublicKey()
	cipher, err := stdRSA.EncryptPKCS1v15(rand.Reader, pub, []byte("stream data"))
	require.NoError(t, err)

	reader := bytes.NewReader(cipher)
	sd := NewStreamDecrypter(reader, kp).(*StreamDecrypter)
	require.NoError(t, sd.Error)

	buf := make([]byte, 6)
	n, err := sd.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "stream", string(buf[:n]))

	n, err = sd.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, " data", string(buf[:n]))

	_, err = sd.Read(buf)
	assert.Equal(t, io.EOF, err)

	t.Run("oaep decrypt success", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		enc := NewStdEncrypter(kp)
		cipher, err := enc.Encrypt([]byte("oaep stream"))
		require.NoError(t, err)

		sd := NewStreamDecrypter(bytes.NewReader(cipher), kp).(*StreamDecrypter)
		out := make([]byte, len("oaep stream"))
		n, err := sd.Read(out)
		require.NoError(t, err)
		assert.Equal(t, "oaep stream", string(out[:n]))
	})

	t.Run("existing error short circuits", func(t *testing.T) {
		sd := &StreamDecrypter{Error: assert.AnError}
		_, err := sd.Read(make([]byte, 1))
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("unexpected EOF handling", func(t *testing.T) {
		short := bytes.NewReader(cipher[:10])
		sd := NewStreamDecrypter(short, kp).(*StreamDecrypter)
		_, err := sd.Read(make([]byte, 5))
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read error propagation", func(t *testing.T) {
		errReader := mock.NewErrorReadWriteCloser(assert.AnError)
		sd := NewStreamDecrypter(errReader, kp).(*StreamDecrypter)
		_, err := sd.Read(make([]byte, 5))
		var readErr ReadError
		require.ErrorAs(t, err, &readErr)
		assert.Equal(t, assert.AnError, readErr.Err)
	})

	t.Run("nil private key", func(t *testing.T) {
		sd := &StreamDecrypter{
			reader:  bytes.NewReader(make([]byte, 256)),
			priKey:  nil,
			keypair: *kp,
		}
		_, err := sd.Read(make([]byte, 100))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, sd.Error)
	})

	t.Run("empty padding", func(t *testing.T) {
		sd := NewStreamDecrypter(bytes.NewReader(cipher), kp).(*StreamDecrypter)
		sd.keypair.Padding = ""
		sd.priKey, _ = kp.ParsePrivateKey()
		_, err := sd.Read(make([]byte, 5))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, sd.Error)
	})

	t.Run("invalid padding", func(t *testing.T) {
		sd := NewStreamDecrypter(bytes.NewReader(cipher), kp).(*StreamDecrypter)
		sd.keypair.Padding = keypair.RsaPaddingScheme("weird")
		sd.priKey, _ = kp.ParsePrivateKey()
		_, err := sd.Read(make([]byte, 5))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, sd.Error)
	})

	t.Run("decrypt error propagates", func(t *testing.T) {
		// Use the priKey.Size() to get block size
		blockSize := sd.priKey.Size()
		sd2 := NewStreamDecrypter(bytes.NewReader(bytes.Repeat([]byte{1}, blockSize)), kp).(*StreamDecrypter)
		_, err := sd2.Read(make([]byte, 5))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, sd2.Error)
	})

	t.Run("empty plaintext triggers final EOF", func(t *testing.T) {
		emptyCipher, err := stdRSA.EncryptPKCS1v15(rand.Reader, pub, []byte{})
		require.NoError(t, err)
		sd := NewStreamDecrypter(bytes.NewReader(emptyCipher), kp).(*StreamDecrypter)
		buf := make([]byte, 1)
		n, err := sd.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("multiple reads with buffered data", func(t *testing.T) {
		kp1 := mustKeyPair(t, keypair.PKCS1)
		pub1, _ := kp1.ParsePublicKey()

		longMsg := []byte("This is a longer message for testing")
		cipher1, err := stdRSA.EncryptPKCS1v15(rand.Reader, pub1, longMsg)
		require.NoError(t, err)

		reader1 := bytes.NewReader(cipher1)
		sd1 := NewStreamDecrypter(reader1, kp1).(*StreamDecrypter)
		require.NoError(t, sd1.Error)

		buf1 := make([]byte, 5)
		totalRead := 0
		var result []byte

		for {
			n, err := sd1.Read(buf1)
			if n > 0 {
				result = append(result, buf1[:n]...)
				totalRead += n
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Equal(t, string(longMsg), string(result))
	})

	t.Run("decrypt with invalid padding", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		sd := NewStreamDecrypter(bytes.NewReader(nil), kp).(*StreamDecrypter)
		sd.keypair.Padding = keypair.RsaPaddingScheme("invalid")
		_, err := sd.decrypt([]byte("data"))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("decrypt with oaep", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		enc := NewStdEncrypter(kp)
		cipher, err := enc.Encrypt([]byte("test"))
		require.NoError(t, err)

		sd := NewStreamDecrypter(bytes.NewReader(nil), kp).(*StreamDecrypter)
		decrypted, err := sd.decrypt(cipher)
		require.NoError(t, err)
		assert.Equal(t, "test", string(decrypted))
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		sd := NewStreamDecrypter(bytes.NewReader(nil), kp).(*StreamDecrypter)
		decrypted, err := sd.decrypt([]byte{})
		assert.NoError(t, err)
		assert.Empty(t, decrypted)
	})
}

func TestStdSigner(t *testing.T) {
	emptyKey := keypair.NewRsaKeyPair()
	emptyKey.SetFormat(keypair.PKCS1)
	s := NewStdSigner(emptyKey)
	assert.IsType(t, SignError{}, s.Error)

	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.OAEP)
	assert.IsType(t, SignError{}, NewStdSigner(kp).Error)

	t.Run("sign pkcs1", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		s := NewStdSigner(kp)
		sign, err := s.Sign([]byte("data"))
		require.NoError(t, err)
		assert.NotEmpty(t, sign)
	})

	t.Run("sign pss", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		s := NewStdSigner(kp)
		sign, err := s.Sign([]byte("data"))
		require.NoError(t, err)
		assert.NotEmpty(t, sign)
	})

	t.Run("existing error short circuits", func(t *testing.T) {
		s := &StdSigner{Error: assert.AnError}
		sign, err := s.Sign([]byte("ignored"))
		assert.Nil(t, sign)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("empty input", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		s := NewStdSigner(kp)
		sign, err := s.Sign(nil)
		assert.Nil(t, sign)
		assert.NoError(t, err)
	})

	t.Run("invalid private key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.PrivateKey = []byte("bad")
		s := NewStdSigner(kp)
		sign, err := s.Sign([]byte("data"))
		assert.Nil(t, sign)
		assert.Error(t, err)
		assert.IsType(t, SignError{}, s.Error)
	})

	t.Run("empty padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Format = ""
		kp.Padding = ""
		s := NewStdSigner(kp)
		_, err := s.Sign([]byte("data"))
		assert.Error(t, err)
	})

	t.Run("invalid padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Padding = keypair.RsaPaddingScheme("weird")
		s := NewStdSigner(kp)
		_, err := s.Sign([]byte("data"))
		assert.Error(t, err)
		assert.IsType(t, SignError{}, s.Error)
	})
}

func TestStdVerifier(t *testing.T) {
	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.OAEP)
	assert.IsType(t, VerifyError{}, NewStdVerifier(kp).Error)

	t.Run("verify pkcs1", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		sign, _ := NewStdSigner(kp).Sign([]byte("data"))
		v := NewStdVerifier(kp)
		valid, err := v.Verify([]byte("data"), sign)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("verify pss", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		sign, _ := NewStdSigner(kp).Sign([]byte("data"))
		v := NewStdVerifier(kp)
		valid, err := v.Verify([]byte("data"), sign)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("existing error short circuits", func(t *testing.T) {
		v := &StdVerifier{Error: assert.AnError}
		valid, err := v.Verify([]byte("data"), []byte("sig"))
		assert.False(t, valid)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("empty inputs", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		v := NewStdVerifier(kp)
		valid, err := v.Verify(nil, nil)
		assert.False(t, valid)
		assert.NoError(t, err)
	})

	t.Run("empty signature with non-empty data", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		v := NewStdVerifier(kp)
		valid, err := v.Verify([]byte("data"), nil)
		assert.False(t, valid)
		assert.Error(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("invalid public key", func(t *testing.T) {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(crypto.SHA256)
		kp.PublicKey = []byte("bad")
		v := NewStdVerifier(kp)
		valid, err := v.Verify([]byte("data"), []byte("sig"))
		assert.False(t, valid)
		assert.Error(t, err)
		assert.IsType(t, VerifyError{}, v.Error)
	})

	t.Run("empty padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Format = ""
		kp.Padding = ""
		v := NewStdVerifier(kp)
		_, err := v.Verify([]byte("data"), []byte("sig"))
		assert.Error(t, err)
	})

	t.Run("invalid padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.Padding = keypair.RsaPaddingScheme("weird")
		v := NewStdVerifier(kp)
		_, err := v.Verify([]byte("data"), []byte("sig"))
		assert.Error(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		v := NewStdVerifier(kp)
		valid, err := v.Verify([]byte("data"), []byte("sig"))
		assert.False(t, valid)
		assert.Error(t, err)
	})
}

func TestStreamSigner(t *testing.T) {
	emptyKey := keypair.NewRsaKeyPair()
	emptyKey.SetFormat(keypair.PKCS1)
	ss := NewStreamSigner(bytes.NewBuffer(nil), emptyKey).(*StreamSigner)
	assert.IsType(t, SignError{}, ss.Error)

	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.OAEP)
	assert.IsType(t, SignError{}, NewStreamSigner(bytes.NewBuffer(nil), kp).(*StreamSigner).Error)

	kp2 := keypair.NewRsaKeyPair()
	kp2.SetFormat(keypair.PKCS1)
	kp2.SetHash(crypto.SHA256)
	kp2.PrivateKey = []byte("bad")
	assert.IsType(t, SignError{}, NewStreamSigner(bytes.NewBuffer(nil), kp2).(*StreamSigner).Error)

	t.Run("pkcs8 defaults to pss", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		ss := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		require.NoError(t, ss.Error)
		assert.Equal(t, keypair.PSS, ss.keypair.Padding)
	})

	kp = mustKeyPair(t, keypair.PKCS1)
	buf := &bytes.Buffer{}
	writer := mock.NewWriteCloser(buf)
	ss = NewStreamSigner(writer, kp).(*StreamSigner)
	require.NoError(t, ss.Error)

	n, err := ss.Write([]byte("stream "))
	require.NoError(t, err)
	assert.Equal(t, 7, n)
	n, err = ss.Write([]byte("sign"))
	require.NoError(t, err)
	assert.Equal(t, 4, n)

	require.NoError(t, ss.Close())
	assert.Greater(t, buf.Len(), 0)

	t.Run("write with preset error", func(t *testing.T) {
		ss := &StreamSigner{Error: assert.AnError}
		_, err := ss.Write([]byte("data"))
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("write empty slice", func(t *testing.T) {
		ss := NewStreamSigner(mock.NewWriteCloser(&bytes.Buffer{}), kp).(*StreamSigner)
		n, err := ss.Write(nil)
		assert.Equal(t, 0, n)
		assert.NoError(t, err)
	})

	t.Run("close with preset error", func(t *testing.T) {
		ss := &StreamSigner{Error: assert.AnError}
		assert.Equal(t, assert.AnError, ss.Close())
	})

	t.Run("close error from writer", func(t *testing.T) {
		writer := mock.NewCloseErrorWriteCloser(&bytes.Buffer{}, assert.AnError)
		ss := NewStreamSigner(writer, kp).(*StreamSigner)
		_, err := ss.Write([]byte("data"))
		require.NoError(t, err)
		assert.Equal(t, assert.AnError, ss.Close())
	})

	t.Run("close write error", func(t *testing.T) {
		writer := mock.NewErrorWriteCloser(assert.AnError)
		ss := NewStreamSigner(writer, kp).(*StreamSigner)
		_, err := ss.Write([]byte("data"))
		require.NoError(t, err)
		assert.Equal(t, assert.AnError, ss.Close())
	})

	t.Run("close without closer", func(t *testing.T) {
		ss := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		_, err := ss.Write([]byte("data"))
		require.NoError(t, err)
		assert.NoError(t, ss.Close())
	})

	t.Run("close sign error with invalid padding", func(t *testing.T) {
		ss := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		_, err := ss.Write([]byte("data"))
		require.NoError(t, err)
		ss.keypair.Padding = ""
		err = ss.Close()
		assert.Error(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("sign with invalid padding", func(t *testing.T) {
		ss := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		ss.keypair.Padding = keypair.RsaPaddingScheme("invalid")
		_, err := ss.sign([]byte("hash"))
		assert.Error(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("sign with pss", func(t *testing.T) {
		pssKP := mustKeyPair(t, keypair.PKCS8)
		ss := NewStreamSigner(&bytes.Buffer{}, pssKP).(*StreamSigner)
		hashed := make([]byte, pssKP.Hash.Size())
		sig, err := ss.sign(hashed)
		assert.NoError(t, err)
		assert.NotEmpty(t, sig)
	})

	t.Run("sign empty data", func(t *testing.T) {
		ss := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		sig, err := ss.sign([]byte{})
		assert.NoError(t, err)
		assert.Empty(t, sig)
	})
}

func TestStreamVerifier(t *testing.T) {
	emptyKey := keypair.NewRsaKeyPair()
	emptyKey.SetFormat(keypair.PKCS1)
	sv := NewStreamVerifier(bytes.NewBuffer(nil), emptyKey).(*StreamVerifier)
	assert.IsType(t, VerifyError{}, sv.Error)

	kp := mustKeyPair(t, keypair.PKCS1)
	kp.SetPadding(keypair.OAEP)
	assert.IsType(t, VerifyError{}, NewStreamVerifier(bytes.NewBuffer(nil), kp).(*StreamVerifier).Error)

	kp2 := keypair.NewRsaKeyPair()
	kp2.SetFormat(keypair.PKCS1)
	kp2.SetHash(crypto.SHA256)
	kp2.PublicKey = []byte("bad")
	assert.IsType(t, VerifyError{}, NewStreamVerifier(bytes.NewBuffer(nil), kp2).(*StreamVerifier).Error)

	t.Run("pkcs8 defaults to pss", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		sv := NewStreamVerifier(bytes.NewBuffer(nil), kp).(*StreamVerifier)
		require.NoError(t, sv.Error)
		assert.Equal(t, keypair.PSS, sv.keypair.Padding)
	})

	validKP := mustKeyPair(t, keypair.PKCS1)
	sign, _ := NewStdSigner(validKP).Sign([]byte("stream verify"))

	t.Run("write and close success", func(t *testing.T) {
		reader := mock.NewFile(sign, "signature")
		defer reader.Close()
		sv := NewStreamVerifier(reader, validKP).(*StreamVerifier)
		require.NoError(t, sv.Error)
		n, err := sv.Write([]byte("stream verify"))
		require.NoError(t, err)
		assert.Equal(t, len("stream verify"), n)
		require.NoError(t, sv.Close())
		assert.True(t, sv.verified)
	})

	t.Run("write with preset error", func(t *testing.T) {
		sv := &StreamVerifier{Error: assert.AnError}
		_, err := sv.Write([]byte("data"))
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("write empty slice", func(t *testing.T) {
		reader := bytes.NewReader(sign)
		sv := NewStreamVerifier(reader, validKP).(*StreamVerifier)
		n, err := sv.Write(nil)
		assert.Equal(t, 0, n)
		assert.NoError(t, err)
	})

	t.Run("close with preset error", func(t *testing.T) {
		sv := &StreamVerifier{Error: assert.AnError}
		assert.Equal(t, assert.AnError, sv.Close())
	})

	t.Run("read error in close", func(t *testing.T) {
		reader := mock.NewErrorReadWriteCloser(assert.AnError)
		sv := NewStreamVerifier(reader, validKP).(*StreamVerifier)
		assert.IsType(t, ReadError{}, sv.Close())
	})

	t.Run("close with empty signature", func(t *testing.T) {
		reader := bytes.NewReader(nil)
		sv := NewStreamVerifier(reader, validKP).(*StreamVerifier)
		require.NoError(t, sv.Close())
	})

	t.Run("verify failure propagates", func(t *testing.T) {
		reader := bytes.NewReader([]byte("bad"))
		sv := NewStreamVerifier(reader, validKP).(*StreamVerifier)
		_, _ = sv.Write([]byte("stream verify"))
		err := sv.Close()
		assert.Error(t, err)
	})

	t.Run("verify close error bubbles", func(t *testing.T) {
		reader := mock.NewCloseErrorReadCloser(bytes.NewReader(sign), assert.AnError)
		sv := NewStreamVerifier(reader, validKP).(*StreamVerifier)
		_, _ = sv.Write([]byte("stream verify"))
		err := sv.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close success without closer", func(t *testing.T) {
		reader := bytes.NewReader(sign)
		sv := NewStreamVerifier(reader, validKP).(*StreamVerifier)
		_, _ = sv.Write([]byte("stream verify"))
		assert.NoError(t, sv.Close())
		assert.True(t, sv.verified)
	})

	t.Run("pss verification success", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		pssSig, _ := NewStdSigner(kp).Sign([]byte("pss data"))
		reader := bytes.NewReader(pssSig)
		sv := NewStreamVerifier(reader, kp).(*StreamVerifier)
		_, err := sv.Write([]byte("pss data"))
		require.NoError(t, err)
		assert.NoError(t, sv.Close())
		assert.True(t, sv.verified)
	})

	t.Run("verify with invalid padding", func(t *testing.T) {
		sv := NewStreamVerifier(bytes.NewReader(sign), validKP).(*StreamVerifier)
		sv.keypair.Padding = keypair.RsaPaddingScheme("invalid")
		_, err := sv.verify([]byte("hash"), sign)
		assert.Error(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with pss", func(t *testing.T) {
		pssKP := mustKeyPair(t, keypair.PKCS8)
		pssSig, _ := NewStdSigner(pssKP).Sign([]byte("test"))
		hasher := pssKP.Hash.New()
		hasher.Write([]byte("test"))
		hashed := hasher.Sum(nil)
		sv := NewStreamVerifier(bytes.NewReader(pssSig), pssKP).(*StreamVerifier)
		valid, err := sv.verify(hashed, pssSig)
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("verify empty hashed data", func(t *testing.T) {
		sv := NewStreamVerifier(bytes.NewReader(sign), validKP).(*StreamVerifier)
		valid, err := sv.verify([]byte{}, sign)
		assert.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("verify with empty padding", func(t *testing.T) {
		sv := NewStreamVerifier(bytes.NewReader(sign), validKP).(*StreamVerifier)
		sv.keypair.Padding = ""
		_, err := sv.verify([]byte("hash"), sign)
		assert.Error(t, err)
		assert.IsType(t, VerifyError{}, err)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("EncryptError", func(t *testing.T) {
		err := EncryptError{Err: errors.New("test error")}
		expected := "crypto/rsa: failed to encrypt data: test error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("DecryptError", func(t *testing.T) {
		err := DecryptError{Err: errors.New("test error")}
		expected := "crypto/rsa: failed to decrypt data: test error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("SignError", func(t *testing.T) {
		err := SignError{Err: errors.New("test error")}
		expected := "crypto/rsa: failed to sign data: test error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("VerifyError", func(t *testing.T) {
		err := VerifyError{Err: errors.New("test error")}
		expected := "crypto/rsa: failed to verify signature: test error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("ReadError", func(t *testing.T) {
		err := ReadError{Err: errors.New("test error")}
		expected := "crypto/rsa: failed to read encrypted data: test error"
		assert.Equal(t, expected, err.Error())
	})
}

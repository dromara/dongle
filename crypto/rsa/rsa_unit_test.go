package rsa

import (
	"bytes"
	"crypto"
	stdRsa "crypto/rsa"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/stretchr/testify/require"
)

type trackingWriter struct {
	bytes.Buffer
	writeErr error
	closeErr error
	closed   bool
}

func (w *trackingWriter) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.Buffer.Write(p)
}

func (w *trackingWriter) Close() error {
	w.closed = true
	return w.closeErr
}

type trackingReader struct {
	io.Reader
	closed *bool
	err    error
}

func (r trackingReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	return r.Reader.Read(p)
}

func (r trackingReader) Close() error {
	if r.closed != nil {
		*r.closed = true
	}
	return nil
}

func mustKeyPair(t *testing.T, format keypair.RsaKeyFormat) *keypair.RsaKeyPair {
	t.Helper()
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(format)
	kp.SetHash(crypto.SHA256)
	require.NoError(t, kp.GenKeyPair(1024))
	return kp
}

func mustSizedKeyPair(t *testing.T, bits int, format keypair.RsaKeyFormat) *keypair.RsaKeyPair {
	t.Helper()
	kp := keypair.NewRsaKeyPair()
	kp.SetFormat(format)
	kp.SetHash(crypto.SHA256)
	require.NoError(t, kp.GenKeyPair(bits))
	return kp
}

func mustStdEncrypter(t *testing.T, kp *keypair.RsaKeyPair) *StdEncrypter {
	t.Helper()
	e := NewStdEncrypter(kp)
	require.NoError(t, e.Error)
	return e
}

func mustStdDecrypter(t *testing.T, kp *keypair.RsaKeyPair) *StdDecrypter {
	t.Helper()
	d := NewStdDecrypter(kp)
	require.NoError(t, d.Error)
	return d
}

func mustStdSigner(t *testing.T, kp *keypair.RsaKeyPair) *StdSigner {
	t.Helper()
	s := NewStdSigner(kp)
	require.NoError(t, s.Error)
	return s
}

func mustStdVerifier(t *testing.T, kp *keypair.RsaKeyPair) *StdVerifier {
	t.Helper()
	v := NewStdVerifier(kp)
	require.NoError(t, v.Error)
	return v
}

func encryptWith(t *testing.T, kp *keypair.RsaKeyPair, data []byte) []byte {
	t.Helper()
	enc := mustStdEncrypter(t, kp)
	out, err := enc.Encrypt(data)
	require.NoError(t, err)
	return out
}

func signWith(t *testing.T, kp *keypair.RsaKeyPair, data []byte) []byte {
	t.Helper()
	signer := mustStdSigner(t, kp)
	signature, err := signer.Sign(data)
	require.NoError(t, err)
	return signature
}

func streamEncrypter(t *testing.T, w io.Writer, kp *keypair.RsaKeyPair) *StreamEncrypter {
	t.Helper()
	e, ok := NewStreamEncrypter(w, kp).(*StreamEncrypter)
	require.True(t, ok)
	return e
}

func streamDecrypter(t *testing.T, r io.Reader, kp *keypair.RsaKeyPair) *StreamDecrypter {
	t.Helper()
	d, ok := NewStreamDecrypter(r, kp).(*StreamDecrypter)
	require.True(t, ok)
	return d
}

func streamSigner(t *testing.T, w io.Writer, kp *keypair.RsaKeyPair) *StreamSigner {
	t.Helper()
	s, ok := NewStreamSigner(w, kp).(*StreamSigner)
	require.True(t, ok)
	return s
}

func streamVerifier(t *testing.T, r io.Reader, kp *keypair.RsaKeyPair) *StreamVerifier {
	t.Helper()
	v, ok := NewStreamVerifier(r, kp).(*StreamVerifier)
	require.True(t, ok)
	return v
}

func TestNewStdEncrypter(t *testing.T) {
	t.Run("defaults with PKCS8", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		e := NewStdEncrypter(kp)
		require.NoError(t, e.Error)
		require.Equal(t, keypair.PublicKey, e.keypair.Type)
		require.Equal(t, keypair.OAEP, e.keypair.Padding)
		require.NotNil(t, e.cache.pubKey)
		require.NotNil(t, e.cache.hash)
	})

	t.Run("pkcs1 default padding", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		e := NewStdEncrypter(kp)
		require.NoError(t, e.Error)
		require.Equal(t, keypair.PKCS1v15, e.keypair.Padding)
	})

	t.Run("private key branch", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		e := NewStdEncrypter(kp)
		require.NoError(t, e.Error)
		require.NotNil(t, e.cache.priKey)
	})

	t.Run("missing public key", func(t *testing.T) {
		e := NewStdEncrypter(&keypair.RsaKeyPair{})
		require.Error(t, e.Error)
		var encErr EncryptError
		require.ErrorAs(t, e.Error, &encErr)
	})

	t.Run("invalid public key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{PublicKey: []byte("bad key"), Type: keypair.PublicKey, Hash: crypto.SHA256}
		e := NewStdEncrypter(kp)
		require.Error(t, e.Error)
	})

	t.Run("missing private key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PrivateKey}
		e := NewStdEncrypter(kp)
		require.Error(t, e.Error)
	})

	t.Run("invalid private key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PrivateKey, PrivateKey: []byte("bad key")}
		e := NewStdEncrypter(kp)
		require.Error(t, e.Error)
	})

	t.Run("empty padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		kp.SetPadding("")
		kp.SetFormat("")
		e := NewStdEncrypter(kp)
		require.Error(t, e.Error)
	})

	t.Run("unsupported padding", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		kp.SetPadding(keypair.PSS)
		e := NewStdEncrypter(kp)
		require.Error(t, e.Error)
	})
}

func TestStdEncrypterEncrypt(t *testing.T) {
	t.Run("preexisting error", func(t *testing.T) {
		expected := errors.New("boom")
		e := &StdEncrypter{Error: expected}
		_, err := e.Encrypt([]byte("data"))
		require.Equal(t, expected, err)
	})

	t.Run("empty source", func(t *testing.T) {
		e := mustStdEncrypter(t, mustKeyPair(t, keypair.PKCS1))
		out, err := e.Encrypt(nil)
		require.NoError(t, err)
		require.Nil(t, out)
	})

	t.Run("public pkcs1v15", func(t *testing.T) {
		e := mustStdEncrypter(t, mustKeyPair(t, keypair.PKCS1))
		out, err := e.Encrypt([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, out)
	})

	t.Run("public oaep", func(t *testing.T) {
		e := mustStdEncrypter(t, mustKeyPair(t, keypair.PKCS8))
		out, err := e.Encrypt([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, out)
	})

	t.Run("private pkcs1v15", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		e := mustStdEncrypter(t, kp)
		out, err := e.Encrypt([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, out)
	})

	t.Run("private oaep", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		kp.SetType(keypair.PrivateKey)
		e := mustStdEncrypter(t, kp)
		out, err := e.Encrypt([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, out)
	})

	t.Run("unsupported padding", func(t *testing.T) {
		e := mustStdEncrypter(t, mustKeyPair(t, keypair.PKCS1))
		e.keypair.Padding = "weird"
		_, err := e.Encrypt([]byte("data"))
		require.Error(t, err)
	})

	t.Run("encryption failure wrapped", func(t *testing.T) {
		kp := mustSizedKeyPair(t, 1024, keypair.PKCS1)
		e := mustStdEncrypter(t, kp)
		tooLong := bytes.Repeat([]byte("a"), e.cache.pubKey.Size())
		_, err := e.Encrypt(tooLong)
		require.Error(t, err)
		var encErr EncryptError
		require.ErrorAs(t, err, &encErr)
	})
}

func TestStreamEncrypterNewAndEncrypt(t *testing.T) {
	t.Run("chunk size calculation public pkcs1v15", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		e := streamEncrypter(t, &bytes.Buffer{}, kp)
		require.NoError(t, e.Error)
		require.Equal(t, e.cache.pubKey.Size()-11, e.chunkSize)
	})

	t.Run("chunk size calculation oaep", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		e := streamEncrypter(t, &bytes.Buffer{}, kp)
		require.NoError(t, e.Error)
		require.Equal(t, e.cache.pubKey.Size()-2*kp.Hash.Size()-2, e.chunkSize)
		require.NotNil(t, e.cache.hash)
	})

	t.Run("private key chunk size", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		e := streamEncrypter(t, &bytes.Buffer{}, kp)
		require.NoError(t, e.Error)
		require.Equal(t, e.cache.priKey.Size()-11, e.chunkSize)
	})

	t.Run("private oaep chunk size", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		kp.SetType(keypair.PrivateKey)
		e := streamEncrypter(t, &bytes.Buffer{}, kp)
		require.NoError(t, e.Error)
		require.Equal(t, e.cache.priKey.Size()-2*kp.Hash.Size()-2, e.chunkSize)
	})

	t.Run("missing key error", func(t *testing.T) {
		e := streamEncrypter(t, &bytes.Buffer{}, &keypair.RsaKeyPair{})
		require.Error(t, e.Error)
	})

	t.Run("empty padding error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding("")
		kp.SetFormat("")
		e := streamEncrypter(t, &bytes.Buffer{}, kp)
		require.Error(t, e.Error)
	})

	t.Run("unsupported padding", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding(keypair.PSS)
		e := streamEncrypter(t, &bytes.Buffer{}, kp)
		require.Error(t, e.Error)
	})

	t.Run("encrypt helper variants", func(t *testing.T) {
		pubPKCS1 := streamEncrypter(t, io.Discard, mustKeyPair(t, keypair.PKCS1))
		_, err := pubPKCS1.encrypt([]byte("hello"))
		require.NoError(t, err)

		pubOAEP := streamEncrypter(t, io.Discard, mustKeyPair(t, keypair.PKCS8))
		_, err = pubOAEP.encrypt([]byte("hello"))
		require.NoError(t, err)

		priPKCS1Kp := mustKeyPair(t, keypair.PKCS1)
		priPKCS1Kp.SetType(keypair.PrivateKey)
		priPKCS1 := streamEncrypter(t, io.Discard, priPKCS1Kp)
		_, err = priPKCS1.encrypt([]byte("hello"))
		require.NoError(t, err)

		priOAEPKp := mustKeyPair(t, keypair.PKCS8)
		priOAEPKp.SetType(keypair.PrivateKey)
		priOAEP := streamEncrypter(t, io.Discard, priOAEPKp)
		_, err = priOAEP.encrypt([]byte("hello"))
		require.NoError(t, err)

		priOAEP.encrypt(nil) // cover empty data path

		pubPKCS1.keypair.Padding = "bad"
		_, err = pubPKCS1.encrypt([]byte("fail"))
		require.Error(t, err)
	})
}

func TestStreamEncrypterWriteAndClose(t *testing.T) {
	t.Run("write with preset error", func(t *testing.T) {
		e := streamEncrypter(t, &bytes.Buffer{}, &keypair.RsaKeyPair{})
		_, err := e.Write([]byte("data"))
		require.Error(t, err)
	})

	t.Run("write empty input", func(t *testing.T) {
		e := streamEncrypter(t, &bytes.Buffer{}, mustKeyPair(t, keypair.PKCS1))
		n, err := e.Write(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("multiple chunks and close flush", func(t *testing.T) {
		kp := mustSizedKeyPair(t, 1024, keypair.PKCS1)
		writer := &trackingWriter{}
		e := streamEncrypter(t, writer, kp)
		require.NoError(t, e.Error)

		data := bytes.Repeat([]byte("a"), e.chunkSize*2+10)
		n, err := e.Write(data)
		require.NoError(t, err)
		require.Equal(t, len(data), n)
		require.Greater(t, writer.Len(), 0)

		err = e.Close()
		require.NoError(t, err)
		require.True(t, writer.closed)
	})

	t.Run("write encryption error", func(t *testing.T) {
		kp := mustSizedKeyPair(t, 1024, keypair.PKCS1)
		writer := &bytes.Buffer{}
		e := streamEncrypter(t, writer, kp)
		require.NoError(t, e.Error)
		e.keypair.Padding = "bad"
		_, err := e.Write(bytes.Repeat([]byte("a"), e.chunkSize))
		require.Error(t, err)
	})

	t.Run("write writer error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		writer := &trackingWriter{writeErr: errors.New("write failed")}
		e := streamEncrypter(t, writer, kp)
		require.NoError(t, e.Error)
		_, err := e.Write(bytes.Repeat([]byte("a"), e.chunkSize))
		require.EqualError(t, err, "write failed")
	})

	t.Run("close with existing error", func(t *testing.T) {
		e := &StreamEncrypter{Error: errors.New("fail")}
		require.EqualError(t, e.Close(), "fail")
	})

	t.Run("close with leftover error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		writer := &trackingWriter{writeErr: errors.New("write fail")}
		e := streamEncrypter(t, writer, kp)
		require.NoError(t, e.Error)
		_, err := e.Write([]byte("hi"))
		require.NoError(t, err)
		require.EqualError(t, e.Close(), "write fail")
	})
}

func TestStreamEncrypterEdgeCases(t *testing.T) {
	t.Run("invalid public key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PublicKey, PublicKey: []byte("bad"), Hash: crypto.SHA256}
		e := streamEncrypter(t, io.Discard, kp)
		require.Error(t, e.Error)
	})

	t.Run("empty private key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PrivateKey}
		e := streamEncrypter(t, io.Discard, kp)
		require.Error(t, e.Error)
	})

	t.Run("invalid private key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PrivateKey, PrivateKey: []byte("bad")}
		e := streamEncrypter(t, io.Discard, kp)
		require.Error(t, e.Error)
	})

	t.Run("encrypt with preset error", func(t *testing.T) {
		expected := errors.New("stop")
		e := &StreamEncrypter{Error: expected}
		_, err := e.encrypt([]byte("data"))
		require.Equal(t, expected, err)
	})

	t.Run("close without buffered data", func(t *testing.T) {
		e := streamEncrypter(t, &bytes.Buffer{}, mustKeyPair(t, keypair.PKCS1))
		require.NoError(t, e.Close())
	})

	t.Run("close with closer and no buffer", func(t *testing.T) {
		writer := &trackingWriter{}
		e := streamEncrypter(t, writer, mustKeyPair(t, keypair.PKCS1))
		require.NoError(t, e.Close())
		require.True(t, writer.closed)
	})

	t.Run("unsupported padding during chunk size", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding("weird")
		e := streamEncrypter(t, io.Discard, kp)
		require.Error(t, e.Error)
	})

	t.Run("close error from closer", func(t *testing.T) {
		writer := &trackingWriter{closeErr: errors.New("close fail")}
		e := streamEncrypter(t, writer, mustKeyPair(t, keypair.PKCS1))
		require.EqualError(t, e.Close(), "close fail")
	})

	t.Run("close encryption error", func(t *testing.T) {
		writer := &bytes.Buffer{}
		e := streamEncrypter(t, writer, mustKeyPair(t, keypair.PKCS1))
		_, err := e.Write([]byte("data"))
		require.NoError(t, err)
		e.keypair.Padding = "bad"
		require.Error(t, e.Close())
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("defaults to private key", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		d := NewStdDecrypter(kp)
		require.NoError(t, d.Error)
		require.Equal(t, keypair.PrivateKey, d.keypair.Type)
		require.NotNil(t, d.cache.priKey)
	})

	t.Run("public key branch", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PublicKey)
		d := NewStdDecrypter(kp)
		require.NoError(t, d.Error)
		require.NotNil(t, d.cache.pubKey)
	})

	t.Run("oaep sets hash", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		d := NewStdDecrypter(kp)
		require.NoError(t, d.Error)
		require.NotNil(t, d.cache.hash)
	})

	t.Run("missing keys and invalid keys", func(t *testing.T) {
		require.Error(t, NewStdDecrypter(&keypair.RsaKeyPair{}).Error)

		kp := &keypair.RsaKeyPair{Type: keypair.PublicKey}
		require.Error(t, NewStdDecrypter(kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PublicKey, PublicKey: []byte("bad"), Hash: crypto.SHA256}
		require.Error(t, NewStdDecrypter(kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PrivateKey}
		require.Error(t, NewStdDecrypter(kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PrivateKey, PrivateKey: []byte("bad key")}
		require.Error(t, NewStdDecrypter(kp).Error)
	})

	t.Run("padding errors", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding("")
		kp.SetFormat("")
		require.Error(t, NewStdDecrypter(kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding(keypair.PSS)
		require.Error(t, NewStdDecrypter(kp).Error)
	})
}

func TestStdDecrypterDecrypt(t *testing.T) {
	t.Run("preexisting error", func(t *testing.T) {
		d := &StdDecrypter{Error: errors.New("nope")}
		_, err := d.Decrypt([]byte("data"))
		require.EqualError(t, err, "nope")
	})

	t.Run("empty input", func(t *testing.T) {
		d := mustStdDecrypter(t, mustKeyPair(t, keypair.PKCS1))
		out, err := d.Decrypt(nil)
		require.NoError(t, err)
		require.Nil(t, out)
	})

	t.Run("private pkcs1v15", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		cipher := encryptWith(t, kp, []byte("hello"))

		kp.SetType(keypair.PrivateKey)
		d := mustStdDecrypter(t, kp)
		plain, err := d.Decrypt(cipher)
		require.NoError(t, err)
		require.Equal(t, []byte("hello"), plain)
	})

	t.Run("private oaep", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		cipher := encryptWith(t, kp, []byte("oaep"))
		kp.SetType(keypair.PrivateKey)
		d := mustStdDecrypter(t, kp)
		plain, err := d.Decrypt(cipher)
		require.NoError(t, err)
		require.Equal(t, []byte("oaep"), plain)
	})

	t.Run("public pkcs1v15", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		cipher := encryptWith(t, kp, []byte("pub decrypt"))

		kp.SetType(keypair.PublicKey)
		d := mustStdDecrypter(t, kp)
		plain, err := d.Decrypt(cipher)
		require.Error(t, err)
		require.Nil(t, plain)
		var decErr DecryptError
		require.ErrorAs(t, err, &decErr)
	})

	t.Run("public oaep", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		kp.SetType(keypair.PrivateKey)
		cipher := encryptWith(t, kp, []byte("pub oaep"))

		kp.SetType(keypair.PublicKey)
		d := mustStdDecrypter(t, kp)
		plain, err := d.Decrypt(cipher)
		require.Error(t, err)
		require.Nil(t, plain)
	})

	t.Run("unsupported padding", func(t *testing.T) {
		d := mustStdDecrypter(t, mustKeyPair(t, keypair.PKCS1))
		d.keypair.Padding = "bad"
		_, err := d.Decrypt([]byte("cipher"))
		require.Error(t, err)
	})

	t.Run("decrypt error wrapped", func(t *testing.T) {
		d := mustStdDecrypter(t, mustKeyPair(t, keypair.PKCS1))
		_, err := d.Decrypt([]byte("short"))
		require.Error(t, err)
		var decErr DecryptError
		require.ErrorAs(t, err, &decErr)
	})
}

func TestStreamDecrypterNew(t *testing.T) {
	t.Run("defaults and hash", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		d := streamDecrypter(t, bytes.NewReader(nil), kp)
		require.NoError(t, d.Error)
		require.NotNil(t, d.cache.hash)
	})

	t.Run("errors", func(t *testing.T) {
		require.Error(t, streamDecrypter(t, bytes.NewReader(nil), &keypair.RsaKeyPair{}).Error)

		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding("")
		kp.SetFormat("")
		require.Error(t, streamDecrypter(t, bytes.NewReader(nil), kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding(keypair.PSS)
		require.Error(t, streamDecrypter(t, bytes.NewReader(nil), kp).Error)
	})
}

func TestStreamDecrypterRead(t *testing.T) {
	t.Run("reads across buffer and eof", func(t *testing.T) {
		kp := mustSizedKeyPair(t, 1024, keypair.PKCS1)
		plain := []byte("streaming plaintext")
		cipher := encryptWith(t, kp, plain)

		kp.SetType(keypair.PrivateKey)
		d := streamDecrypter(t, bytes.NewReader(cipher), kp)
		require.NoError(t, d.Error)

		buf := make([]byte, 5)
		var out bytes.Buffer
		for {
			n, err := d.Read(buf)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			out.Write(buf[:n])
		}
		require.Equal(t, plain, out.Bytes())
	})

	t.Run("public oaep decrypt", func(t *testing.T) {
		kp := mustSizedKeyPair(t, 1024, keypair.PKCS8)
		kp.SetType(keypair.PrivateKey)
		cipher := encryptWith(t, kp, []byte("public oaep stream"))

		kp.SetType(keypair.PublicKey)
		d := streamDecrypter(t, bytes.NewReader(cipher), kp)
		require.NoError(t, d.Error)

		out := make([]byte, len(cipher))
		n, err := d.Read(out)
		require.Error(t, err)
		require.Zero(t, n)
	})

	t.Run("preset error", func(t *testing.T) {
		d := &StreamDecrypter{Error: errors.New("stop")}
		_, err := d.Read(make([]byte, 5))
		require.EqualError(t, err, "stop")
	})

	t.Run("unexpected eof", func(t *testing.T) {
		kp := mustSizedKeyPair(t, 1024, keypair.PKCS1)
		cipher := encryptWith(t, kp, []byte("short"))
		kp.SetType(keypair.PrivateKey)
		reader := bytes.NewReader(cipher[:len(cipher)-1])
		d := streamDecrypter(t, reader, kp)
		_, err := d.Read(make([]byte, 5))
		require.Equal(t, io.EOF, err)
	})

	t.Run("read error wrapped", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		d := streamDecrypter(t, trackingReader{Reader: bytes.NewReader(nil), err: errors.New("read fail")}, kp)
		_, err := d.Read(make([]byte, 5))
		require.Error(t, err)
		var readErr ReadError
		require.ErrorAs(t, err, &readErr)
	})

	t.Run("decrypt error bubble", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		blockSize := mustStdDecrypter(t, kp).cache.priKey.Size()
		badCipher := bytes.Repeat([]byte{0}, blockSize)
		d := streamDecrypter(t, bytes.NewReader(badCipher), kp)
		_, err := d.Read(make([]byte, 10))
		require.Error(t, err)
	})
}

func TestStreamDecrypterAdditionalBranches(t *testing.T) {
	t.Run("invalid public key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PublicKey, PublicKey: []byte("bad"), Hash: crypto.SHA256}
		d := streamDecrypter(t, bytes.NewReader(nil), kp)
		require.Error(t, d.Error)
	})

	t.Run("empty public key type", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PublicKey}
		d := streamDecrypter(t, bytes.NewReader(nil), kp)
		require.Error(t, d.Error)
	})

	t.Run("invalid private key", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PrivateKey, PrivateKey: []byte("bad")}
		d := streamDecrypter(t, bytes.NewReader(nil), kp)
		require.Error(t, d.Error)
	})

	t.Run("decrypt helper coverage", func(t *testing.T) {
		pubPKCS1 := mustKeyPair(t, keypair.PKCS1)
		pubPKCS1.SetType(keypair.PublicKey)
		d1 := streamDecrypter(t, bytes.NewReader(nil), pubPKCS1)
		_, _ = d1.decrypt(make([]byte, d1.cache.pubKey.Size()))

		pubOAEP := mustKeyPair(t, keypair.PKCS8)
		pubOAEP.SetType(keypair.PublicKey)
		d2 := streamDecrypter(t, bytes.NewReader(nil), pubOAEP)
		_, _ = d2.decrypt(make([]byte, d2.cache.pubKey.Size()))

		priPKCS1 := mustKeyPair(t, keypair.PKCS1)
		priPKCS1.SetType(keypair.PrivateKey)
		d3 := streamDecrypter(t, bytes.NewReader(nil), priPKCS1)
		_, _ = d3.decrypt(make([]byte, d3.cache.priKey.Size()))

		priOAEP := mustKeyPair(t, keypair.PKCS8)
		priOAEP.SetType(keypair.PrivateKey)
		d4 := streamDecrypter(t, bytes.NewReader(nil), priOAEP)
		_, _ = d4.decrypt(make([]byte, d4.cache.priKey.Size()))

		d4.keypair.Padding = "bad"
		_, err := d4.decrypt([]byte{1})
		require.Error(t, err)

		dst, err := (&StreamDecrypter{}).decrypt(nil)
		require.NoError(t, err)
		require.Nil(t, dst)

		preset := &StreamDecrypter{Error: errors.New("stop")}
		_, err = preset.decrypt([]byte("x"))
		require.EqualError(t, err, "stop")
	})

	t.Run("zero block size read", func(t *testing.T) {
		d := &StreamDecrypter{reader: bytes.NewReader(nil)}
		_, err := d.Read(make([]byte, 1))
		require.Equal(t, io.EOF, err)
	})
}

func TestNewStdSigner(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		s := NewStdSigner(kp)
		require.NoError(t, s.Error)
		require.NotNil(t, s.cache.priKey)
	})

	t.Run("public key branch", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PublicKey)
		s := NewStdSigner(kp)
		require.NoError(t, s.Error)
		require.NotNil(t, s.cache.pubKey)
	})

	t.Run("padding and key errors", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PublicKey}
		require.Error(t, NewStdSigner(kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PublicKey, PublicKey: []byte("bad"), Hash: crypto.SHA256}
		require.Error(t, NewStdSigner(kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PrivateKey}
		require.Error(t, NewStdSigner(kp).Error)

		kp = &keypair.RsaKeyPair{PrivateKey: []byte("bad"), Type: keypair.PrivateKey}
		require.Error(t, NewStdSigner(kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding("")
		kp.SetFormat("")
		require.Error(t, NewStdSigner(kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding(keypair.OAEP)
		require.Error(t, NewStdSigner(kp).Error)
	})
}

func TestStdSignerSign(t *testing.T) {
	t.Run("preset error", func(t *testing.T) {
		s := &StdSigner{Error: errors.New("bad")}
		_, err := s.Sign([]byte("data"))
		require.EqualError(t, err, "bad")
	})

	t.Run("empty input", func(t *testing.T) {
		s := mustStdSigner(t, mustKeyPair(t, keypair.PKCS1))
		sign, err := s.Sign(nil)
		require.NoError(t, err)
		require.Nil(t, sign)
	})

	t.Run("public pkcs1v15", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PublicKey)
		s := mustStdSigner(t, kp)
		sign, err := s.Sign([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, sign)
	})

	t.Run("public pss", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		kp.SetType(keypair.PublicKey)
		s := mustStdSigner(t, kp)
		sign, err := s.Sign([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, sign)
	})

	t.Run("private pkcs1v15", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		s := mustStdSigner(t, kp)
		sign, err := s.Sign([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, sign)
	})

	t.Run("private pss", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		kp.SetType(keypair.PrivateKey)
		s := mustStdSigner(t, kp)
		sign, err := s.Sign([]byte("hello"))
		require.NoError(t, err)
		require.NotEmpty(t, sign)
	})

	t.Run("unsupported padding", func(t *testing.T) {
		s := mustStdSigner(t, mustKeyPair(t, keypair.PKCS1))
		s.keypair.Padding = "bad"
		_, err := s.Sign([]byte("data"))
		require.Error(t, err)
	})

	t.Run("signer returns error", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PublicKey)
		s := mustStdSigner(t, kp)
		s.cache.pubKey = &stdRsa.PublicKey{}
		_, err := s.Sign([]byte("data"))
		require.Error(t, err)
	})
}

func TestStreamSigner(t *testing.T) {
	t.Run("write and close", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		writer := &trackingWriter{}
		s := streamSigner(t, writer, kp)
		require.NoError(t, s.Error)
		n, err := s.Write([]byte("payload"))
		require.NoError(t, err)
		require.Equal(t, 7, n)
		require.NoError(t, s.Close())
		require.True(t, writer.closed)
		require.Greater(t, writer.Len(), 0)
	})

	t.Run("preset error", func(t *testing.T) {
		s := &StreamSigner{Error: errors.New("fail")}
		_, err := s.Write([]byte("data"))
		require.EqualError(t, err, "fail")
		require.EqualError(t, s.Close(), "fail")
	})

	t.Run("empty write", func(t *testing.T) {
		s := streamSigner(t, io.Discard, mustKeyPair(t, keypair.PKCS1))
		n, err := s.Write(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("sign helper paths", func(t *testing.T) {
		s := streamSigner(t, io.Discard, mustKeyPair(t, keypair.PKCS1))
		_, err := s.sign(nil)
		require.NoError(t, err)

		s.keypair.Padding = "bad"
		_, err = s.sign([]byte{1, 2, 3})
		require.Error(t, err)
	})

	t.Run("writer error on close", func(t *testing.T) {
		writer := &trackingWriter{writeErr: errors.New("write fail")}
		s := streamSigner(t, writer, mustKeyPair(t, keypair.PKCS1))
		require.NoError(t, s.Error)
		_, err := s.Write([]byte("data"))
		require.NoError(t, err)
		require.EqualError(t, s.Close(), "write fail")
	})

	t.Run("sign failure bubbled", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PublicKey)
		writer := &trackingWriter{}
		s := streamSigner(t, writer, kp)
		require.NoError(t, s.Error)
		s.cache.pubKey = &stdRsa.PublicKey{}
		_, err := s.Write([]byte("data"))
		require.NoError(t, err)
		require.Error(t, s.Close())
	})
}

func TestStreamSignerAdditional(t *testing.T) {
	t.Run("constructor errors", func(t *testing.T) {
		kp := &keypair.RsaKeyPair{Type: keypair.PublicKey}
		require.Error(t, streamSigner(t, io.Discard, kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PublicKey, PublicKey: []byte("bad"), Hash: crypto.SHA256}
		require.Error(t, streamSigner(t, io.Discard, kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PrivateKey}
		require.Error(t, streamSigner(t, io.Discard, kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PrivateKey, PrivateKey: []byte("bad")}
		require.Error(t, streamSigner(t, io.Discard, kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetFormat("")
		kp.SetPadding("")
		require.Error(t, streamSigner(t, io.Discard, kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding(keypair.OAEP)
		require.Error(t, streamSigner(t, io.Discard, kp).Error)
	})

	t.Run("sign helper combinations", func(t *testing.T) {
		pubPKCS1 := mustKeyPair(t, keypair.PKCS1)
		pubPKCS1.SetType(keypair.PublicKey)
		s1 := streamSigner(t, io.Discard, pubPKCS1)
		_, err := s1.sign(make([]byte, s1.keypair.Hash.Size()))
		require.NoError(t, err)

		pubPSS := mustKeyPair(t, keypair.PKCS8)
		pubPSS.SetType(keypair.PublicKey)
		s2 := streamSigner(t, io.Discard, pubPSS)
		_, err = s2.sign(make([]byte, s2.keypair.Hash.Size()))
		require.NoError(t, err)

		privPSS := mustKeyPair(t, keypair.PKCS8)
		privPSS.SetType(keypair.PrivateKey)
		s3 := streamSigner(t, io.Discard, privPSS)
		_, err = s3.sign(make([]byte, s3.keypair.Hash.Size()))
		require.NoError(t, err)

		errSigner := &StreamSigner{Error: errors.New("stop")}
		_, err = errSigner.sign([]byte{1})
		require.EqualError(t, err, "stop")
	})

	t.Run("close without writes", func(t *testing.T) {
		s := streamSigner(t, &bytes.Buffer{}, mustKeyPair(t, keypair.PKCS1))
		require.NoError(t, s.Close())
	})
}

func TestNewStdVerifier(t *testing.T) {
	t.Run("pkcs1 defaults", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		v := NewStdVerifier(kp)
		require.NoError(t, v.Error)
		require.Equal(t, keypair.PKCS1v15, v.keypair.Padding)
	})

	t.Run("pkcs8 defaults", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		v := NewStdVerifier(kp)
		require.NoError(t, v.Error)
		require.Equal(t, keypair.PSS, v.keypair.Padding)
	})

	t.Run("errors", func(t *testing.T) {
		require.Error(t, NewStdVerifier(&keypair.RsaKeyPair{}).Error)

		kp := &keypair.RsaKeyPair{PublicKey: []byte("bad"), Hash: crypto.SHA256}
		require.Error(t, NewStdVerifier(kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding("")
		kp.SetFormat("")
		require.Error(t, NewStdVerifier(kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding(keypair.OAEP)
		require.Error(t, NewStdVerifier(kp).Error)
	})
}

func TestStdVerifierVerify(t *testing.T) {
	t.Run("preset error", func(t *testing.T) {
		v := &StdVerifier{Error: errors.New("fail")}
		_, err := v.Verify([]byte("data"), []byte("sig"))
		require.EqualError(t, err, "fail")
	})

	t.Run("empty inputs", func(t *testing.T) {
		v := mustStdVerifier(t, mustKeyPair(t, keypair.PKCS1))
		ok, err := v.Verify(nil, []byte("sig"))
		require.False(t, ok)
		require.NoError(t, err)

		ok, err = v.Verify([]byte("data"), nil)
		require.False(t, ok)
		require.Error(t, err)
	})

	t.Run("pkcs1 verify", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		sig := signWith(t, kp, []byte("hello"))
		v := mustStdVerifier(t, kp)
		ok, err := v.Verify([]byte("hello"), sig)
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("pss verify", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS8)
		sig := signWith(t, kp, []byte("pss"))
		v := mustStdVerifier(t, kp)
		ok, err := v.Verify([]byte("pss"), sig)
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("invalid signature", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		v := mustStdVerifier(t, kp)
		ok, err := v.Verify([]byte("hello"), []byte("bad"))
		require.False(t, ok)
		require.Error(t, err)
	})

	t.Run("unsupported padding", func(t *testing.T) {
		v := mustStdVerifier(t, mustKeyPair(t, keypair.PKCS1))
		v.keypair.Padding = "bad"
		_, err := v.Verify([]byte("data"), []byte("sig"))
		require.Error(t, err)
	})
}

func TestStreamVerifier(t *testing.T) {
	t.Run("public verification", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		sig := signWith(t, kp, []byte("stream verify"))

		closed := false
		reader := trackingReader{Reader: bytes.NewReader(sig), closed: &closed}
		v := streamVerifier(t, reader, kp)
		require.NoError(t, v.Error)

		n, err := v.Write([]byte("stream verify"))
		require.NoError(t, err)
		require.Equal(t, len("stream verify"), n)
		require.NoError(t, v.Close())
		require.True(t, closed)
		require.True(t, v.verified)
	})

	t.Run("private verification branch", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		kp.SetType(keypair.PrivateKey)
		sig := signWith(t, kp, []byte("private verify"))

		v := streamVerifier(t, bytes.NewReader(sig), kp)
		require.NoError(t, v.Error)
		_, err := v.Write([]byte("private verify"))
		require.NoError(t, err)
		require.NoError(t, v.Close())
	})

	t.Run("preset error", func(t *testing.T) {
		v := &StreamVerifier{Error: errors.New("fail")}
		_, err := v.Write([]byte("data"))
		require.EqualError(t, err, "fail")
		require.EqualError(t, v.Close(), "fail")
	})

	t.Run("empty write", func(t *testing.T) {
		v := streamVerifier(t, bytes.NewReader(nil), mustKeyPair(t, keypair.PKCS1))
		n, err := v.Write(nil)
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("verify helper variants", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		v := streamVerifier(t, bytes.NewReader(nil), kp)
		require.NoError(t, v.Error)
		_, err := v.verify(nil, []byte("sig"))
		require.NoError(t, err)

		v.keypair.Padding = "bad"
		_, err = v.verify([]byte{1}, []byte("sig"))
		require.Error(t, err)
	})

	t.Run("reader error", func(t *testing.T) {
		reader := trackingReader{Reader: bytes.NewReader(nil), err: errors.New("read fail")}
		v := streamVerifier(t, reader, mustKeyPair(t, keypair.PKCS1))
		require.NoError(t, v.Error)
		require.Error(t, v.Close())
	})

	t.Run("empty signature", func(t *testing.T) {
		v := streamVerifier(t, bytes.NewReader(nil), mustKeyPair(t, keypair.PKCS1))
		require.NoError(t, v.Close())
	})

	t.Run("invalid signature", func(t *testing.T) {
		kp := mustKeyPair(t, keypair.PKCS1)
		v := streamVerifier(t, bytes.NewReader([]byte("bad")), kp)
		require.NoError(t, v.Error)
		_, err := v.Write([]byte("payload"))
		require.NoError(t, err)
		require.Error(t, v.Close())
	})
}

func TestStreamVerifierAdditional(t *testing.T) {
	t.Run("constructor errors", func(t *testing.T) {
		require.Error(t, streamVerifier(t, bytes.NewReader(nil), &keypair.RsaKeyPair{}).Error)

		kp := &keypair.RsaKeyPair{Type: keypair.PrivateKey}
		require.Error(t, streamVerifier(t, bytes.NewReader(nil), kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PublicKey, PublicKey: []byte("bad"), Hash: crypto.SHA256}
		require.Error(t, streamVerifier(t, bytes.NewReader(nil), kp).Error)

		kp = &keypair.RsaKeyPair{Type: keypair.PrivateKey, PrivateKey: []byte("bad")}
		require.Error(t, streamVerifier(t, bytes.NewReader(nil), kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding("")
		kp.SetFormat("")
		require.Error(t, streamVerifier(t, bytes.NewReader(nil), kp).Error)

		kp = mustKeyPair(t, keypair.PKCS1)
		kp.SetPadding(keypair.OAEP)
		require.Error(t, streamVerifier(t, bytes.NewReader(nil), kp).Error)
	})

	t.Run("verify helper combinations", func(t *testing.T) {
		pubPSS := mustKeyPair(t, keypair.PKCS8)
		v1 := streamVerifier(t, bytes.NewReader(nil), pubPSS)
		_, err := v1.verify(make([]byte, v1.keypair.Hash.Size()), []byte{1, 2, 3})
		require.Error(t, err)

		privPKCS1 := mustKeyPair(t, keypair.PKCS1)
		privPKCS1.SetType(keypair.PrivateKey)
		v2 := streamVerifier(t, bytes.NewReader(nil), privPKCS1)
		_, err = v2.verify(make([]byte, v2.keypair.Hash.Size()), []byte{1})
		require.Error(t, err)

		privPSS := mustKeyPair(t, keypair.PKCS8)
		privPSS.SetType(keypair.PrivateKey)
		v3 := streamVerifier(t, bytes.NewReader(nil), privPSS)
		_, err = v3.verify(make([]byte, v3.keypair.Hash.Size()), []byte{1})
		require.Error(t, err)

		preset := &StreamVerifier{Error: errors.New("stop")}
		_, err = preset.verify([]byte{1}, []byte{2})
		require.EqualError(t, err, "stop")

		v3.keypair.Padding = "bad"
		_, err = v3.verify([]byte{1}, []byte{2})
		require.Error(t, err)
	})
}

func TestErrorMessages(t *testing.T) {
	base := errors.New("boom")
	require.Contains(t, EncryptError{Err: base}.Error(), "boom")
	require.Contains(t, DecryptError{Err: base}.Error(), "boom")
	require.Contains(t, SignError{Err: base}.Error(), "boom")
	require.Contains(t, VerifyError{Err: base}.Error(), "boom")
	require.Contains(t, ReadError{Err: base}.Error(), "boom")
}

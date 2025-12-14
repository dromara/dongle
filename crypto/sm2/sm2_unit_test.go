package sm2

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/dromara/dongle/crypto/internal/sm2"
	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

func mustKeyPair(t *testing.T) *keypair.Sm2KeyPair {
	t.Helper()
	kp := keypair.NewSm2KeyPair()
	if !assert.NoError(t, kp.GenKeyPair()) {
		t.FailNow()
	}
	return kp
}

func TestStdEncryptDecrypt(t *testing.T) {
	kp := mustKeyPair(t)
	enc := NewStdEncrypter(kp)
	assert.NoError(t, enc.Error)

	dec := NewStdDecrypter(kp)
	assert.NoError(t, dec.Error)

	cipher, err := enc.Encrypt([]byte("hello"))
	assert.NoError(t, err)

	plain, err := dec.Decrypt(cipher)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), plain)

	emptyOut, err := enc.Encrypt(nil)
	assert.NoError(t, err)
	assert.Nil(t, emptyOut)

	assert.EqualError(t, NewStdEncrypter(&keypair.Sm2KeyPair{}).Error, EncryptError{Err: keypair.EmptyPublicKeyError{}}.Error())
	assert.Error(t, NewStdEncrypter(&keypair.Sm2KeyPair{PublicKey: []byte("bad")}).Error)

	enc.cache.pubKey = nil // force EncryptError branch
	_, err = enc.Encrypt([]byte("x"))
	assert.IsType(t, EncryptError{}, err)

	enc.Error = errors.New("preset")
	_, err = enc.Encrypt([]byte("x"))
	assert.EqualError(t, err, "preset")
}

func TestStdDecryptErrors(t *testing.T) {
	kp := mustKeyPair(t)
	d := NewStdDecrypter(kp)
	assert.NoError(t, d.Error)

	nilOut, err := d.Decrypt(nil)
	assert.NoError(t, err)
	assert.Nil(t, nilOut)

	assert.EqualError(t, NewStdDecrypter(&keypair.Sm2KeyPair{}).Error, DecryptError{Err: keypair.EmptyPrivateKeyError{}}.Error())
	assert.Error(t, NewStdDecrypter(&keypair.Sm2KeyPair{PrivateKey: []byte("bad")}).Error)

	d.cache.priKey = nil // force DecryptError branch
	_, err = d.Decrypt([]byte{0x00})
	assert.IsType(t, DecryptError{}, err)

	d.Error = errors.New("preset")
	_, err = d.Decrypt([]byte("data"))
	assert.EqualError(t, err, "preset")
}

func TestStreamEncrypterAndDecrypter(t *testing.T) {
	kp := mustKeyPair(t)
	writer := mock.NewFile(nil, "cipher")
	se := NewStreamEncrypter(writer, kp).(*StreamEncrypter)
	assert.NoError(t, se.Error)

	n, err := se.Write([]byte("foo"))
	assert.NoError(t, err)
	assert.Equal(t, 3, n)

	n, err = se.Write([]byte("bar"))
	assert.NoError(t, err)
	assert.Equal(t, 3, n)

	assert.NoError(t, se.Close())

	sd := NewStreamDecrypter(bytes.NewReader(writer.Bytes()), kp)
	out, err := io.ReadAll(sd)
	assert.NoError(t, err)
	assert.Equal(t, []byte("foobar"), out)

	// empty write
	se = NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
	n, err = se.Write(nil)
	assert.NoError(t, err)
	assert.Zero(t, n)

	// preset error on write
	se = &StreamEncrypter{Error: errors.New("stop")}
	_, err = se.Write([]byte("x"))
	assert.EqualError(t, err, "stop")

	// missing and invalid public keys
	assert.Error(t, NewStreamEncrypter(&bytes.Buffer{}, &keypair.Sm2KeyPair{}).(*StreamEncrypter).Error)
	assert.Error(t, NewStreamEncrypter(&bytes.Buffer{}, &keypair.Sm2KeyPair{PublicKey: []byte("bad")}).(*StreamEncrypter).Error)

	// Close with empty buffer and closer
	emptyWriter := mock.NewFile(nil, "empty")
	se = NewStreamEncrypter(emptyWriter, kp).(*StreamEncrypter)
	assert.NoError(t, se.Close())

	// encrypt error path
	errWriter := mock.NewFile(nil, "err")
	se = NewStreamEncrypter(errWriter, kp).(*StreamEncrypter)
	se.cache.pubKey = nil
	se.buffer = []byte("x")
	assert.IsType(t, EncryptError{}, se.Close())

	// writer error path
	failingWriter := mock.NewErrorFile(errors.New("write fail"))
	se = NewStreamEncrypter(failingWriter, kp).(*StreamEncrypter)
	_, err = se.Write([]byte("data"))
	assert.NoError(t, err)
	assert.EqualError(t, se.Close(), "write fail")

	// writer without closer path
	plainWriter := &bytes.Buffer{}
	se = NewStreamEncrypter(plainWriter, kp).(*StreamEncrypter)
	_, err = se.Write([]byte("plain"))
	assert.NoError(t, err)
	assert.NoError(t, se.Close())

	// empty buffer with writer lacking Close
	se = NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
	assert.NoError(t, se.Close())

	// close error path with closer (no buffered data)
	closeErrWriter := mock.NewErrorFile(errors.New("close fail"))
	se = NewStreamEncrypter(closeErrWriter, kp).(*StreamEncrypter)
	assert.EqualError(t, se.Close(), "close fail")
	se = &StreamEncrypter{Error: errors.New("block")}
	assert.EqualError(t, se.Close(), "block")
}

func TestStreamDecrypterReadCases(t *testing.T) {
	kp := mustKeyPair(t)

	// preset error
	d := &StreamDecrypter{Error: errors.New("stop")}
	_, err := d.Read(make([]byte, 1))
	assert.EqualError(t, err, "stop")

	// missing / invalid private keys
	assert.Error(t, NewStreamDecrypter(bytes.NewReader(nil), &keypair.Sm2KeyPair{}).(*StreamDecrypter).Error)
	assert.Error(t, NewStreamDecrypter(bytes.NewReader(nil), &keypair.Sm2KeyPair{PrivateKey: []byte("bad")}).(*StreamDecrypter).Error)

	// empty cipher -> EOF
	d = NewStreamDecrypter(bytes.NewReader(nil), kp).(*StreamDecrypter)
	n, err := d.Read(make([]byte, 2))
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)

	// reader error
	d = NewStreamDecrypter(mock.NewErrorFile(errors.New("read fail")), kp).(*StreamDecrypter)
	_, err = d.Read(make([]byte, 2))
	assert.EqualError(t, err, ReadError{Err: errors.New("read fail")}.Error())

	// decrypt error
	d = NewStreamDecrypter(bytes.NewReader([]byte{0x00}), kp).(*StreamDecrypter)
	_, err = d.Read(make([]byte, 4))
	assert.IsType(t, DecryptError{}, err)

	// success with multiple reads
	enc := NewStdEncrypter(kp)
	cipher, _ := enc.Encrypt([]byte("split"))
	d = NewStreamDecrypter(bytes.NewReader(cipher), kp).(*StreamDecrypter)
	buf := make([]byte, 3)
	n, err = d.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 3, n)
	n, err = d.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 2, n)
}

func TestStdSignVerify(t *testing.T) {
	kp := mustKeyPair(t)
	s := NewStdSigner(kp)
	assert.NoError(t, s.Error)

	sig, err := s.Sign([]byte("msg"))
	assert.NoError(t, err)

	v := NewStdVerifier(kp)
	assert.NoError(t, v.Error)

	valid, err := v.Verify([]byte("msg"), sig)
	assert.NoError(t, err)
	assert.True(t, valid)

	// verify failure sets error and blocks subsequent calls
	badSig := append([]byte{}, sig...)
	badSig[0] ^= 0xFF
	valid, err = v.Verify([]byte("msg"), badSig)
	assert.False(t, valid)
	assert.IsType(t, VerifyError{}, err)
	_, err = v.Verify([]byte("msg"), sig)
	assert.IsType(t, VerifyError{}, err)

	// reset verifier for remaining cases
	v = NewStdVerifier(kp)
	assert.NoError(t, v.Error)

	// empty input
	sig, err = s.Sign(nil)
	assert.NoError(t, err)
	assert.Nil(t, sig)
	valid, err = v.Verify(nil, sig)
	assert.NoError(t, err)
	assert.False(t, valid)

	// missing/invalid keys
	assert.Error(t, NewStdSigner(&keypair.Sm2KeyPair{}).Error)
	assert.Error(t, NewStdSigner(&keypair.Sm2KeyPair{PrivateKey: []byte("bad")}).Error)
	assert.Error(t, NewStdVerifier(&keypair.Sm2KeyPair{}).Error)
	assert.Error(t, NewStdVerifier(&keypair.Sm2KeyPair{PublicKey: []byte("bad")}).Error)

	// empty signature error
	_, err = v.Verify([]byte("msg"), nil)
	assert.EqualError(t, err, VerifyError{Err: keypair.EmptySignatureError{}}.Error())

}

func TestStreamSignerAndVerifier(t *testing.T) {
	kp := mustKeyPair(t)
	writer := mock.NewFile(nil, "sign")
	ss := NewStreamSigner(writer, kp).(*StreamSigner)
	assert.NoError(t, ss.Error)

	_, err := ss.Write([]byte("hello "))
	assert.NoError(t, err)
	_, err = ss.Write([]byte("world"))
	assert.NoError(t, err)
	assert.NoError(t, ss.Close())

	// verify via stream verifier (reader implements Close)
	sv := NewStreamVerifier(mock.NewFile(writer.Bytes(), "sig"), kp).(*StreamVerifier)
	assert.NoError(t, sv.Error)
	_, err = sv.Write([]byte("hello world"))
	assert.NoError(t, err)
	assert.NoError(t, sv.Close())
	assert.True(t, sv.verified)

	// verifier without closer path
	sv = NewStreamVerifier(bytes.NewReader(writer.Bytes()), kp).(*StreamVerifier)
	_, err = sv.Write([]byte("hello world"))
	assert.NoError(t, err)
	assert.NoError(t, sv.Close())

	// preset errors and empty writes
	ss = &StreamSigner{Error: errors.New("stop")}
	_, err = ss.Write([]byte("x"))
	assert.EqualError(t, err, "stop")
	ss = NewStreamSigner(mock.NewFile(nil, "empty write"), kp).(*StreamSigner)
	n, err := ss.Write(nil)
	assert.NoError(t, err)
	assert.Zero(t, n)

	sv = &StreamVerifier{Error: errors.New("blocked")}
	_, err = sv.Write([]byte("x"))
	assert.EqualError(t, err, "blocked")
	sv = NewStreamVerifier(bytes.NewReader(nil), kp).(*StreamVerifier)
	n, err = sv.Write(nil)
	assert.NoError(t, err)
	assert.Zero(t, n)

	// Close when no data/signature
	ss = NewStreamSigner(mock.NewFile(nil, "no data"), kp).(*StreamSigner)
	assert.NoError(t, ss.Close())
	sv = NewStreamVerifier(bytes.NewReader(nil), kp).(*StreamVerifier)
	assert.NoError(t, sv.Close())

	// writer/read errors
	ss = NewStreamSigner(mock.NewErrorFile(errors.New("write fail")), kp).(*StreamSigner)
	_, err = ss.Write([]byte("x"))
	assert.NoError(t, err)
	assert.EqualError(t, ss.Close(), SignError{Err: errors.New("write fail")}.Error())

	sv = NewStreamVerifier(mock.NewErrorFile(errors.New("read fail")), kp).(*StreamVerifier)
	assert.EqualError(t, sv.Close(), ReadError{Err: errors.New("read fail")}.Error())

	// verify failure sets error
	sv = NewStreamVerifier(bytes.NewReader([]byte("bad sig")), kp).(*StreamVerifier)
	_, err = sv.Write([]byte("data"))
	assert.NoError(t, err)
	assert.IsType(t, VerifyError{}, sv.Close())
	_, err = sv.Write([]byte("again"))
	assert.IsType(t, VerifyError{}, err)

	// sign error branch (invalid private key)
	badKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: sm2.NewCurve()}, D: big.NewInt(0)}
	ss = &StreamSigner{
		writer:  &bytes.Buffer{},
		keypair: *kp,
		cache:   cache{priKey: badKey},
	}
	ss.buffer = []byte("data")
	assert.IsType(t, SignError{}, ss.Close())

	// StreamSigner with writer lacking Close
	noCloseSigner := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
	_, err = noCloseSigner.Write([]byte("abc"))
	assert.NoError(t, err)
	assert.NoError(t, noCloseSigner.Close())

	// empty buffer with closer
	emptyCloserSigner := NewStreamSigner(mock.NewFile(nil, "empty closer"), kp).(*StreamSigner)
	assert.NoError(t, emptyCloserSigner.Close())

	// empty buffer with writer lacking Close
	plainEmptySigner := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
	assert.NoError(t, plainEmptySigner.Close())

	// close error when signing data
	closeAfterSign := mock.NewErrorFile(errors.New("sign close"))
	ss = NewStreamSigner(closeAfterSign, kp).(*StreamSigner)
	assert.EqualError(t, ss.Close(), "sign close")

	// close error with empty buffer
	emptyCloseErr := mock.NewErrorFile(errors.New("empty close"))
	ss = NewStreamSigner(emptyCloseErr, kp).(*StreamSigner)
	assert.EqualError(t, ss.Close(), "empty close")

	// StreamSigner error branches
	errSigner := &StreamSigner{Error: errors.New("blocked")}
	_, err = errSigner.sign([]byte("x"))
	assert.EqualError(t, err, "blocked")
	lengthOnly := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
	_, err = lengthOnly.sign(nil)
	assert.NoError(t, err)
	assert.EqualError(t, errSigner.Close(), "blocked")

	// StreamVerifier verify helper paths
	sv = &StreamVerifier{keypair: *kp, cache: cache{pubKey: nil}}
	valid, err := sv.verify(nil, nil)
	assert.False(t, valid)
	assert.NoError(t, err)

	assert.Error(t, NewStreamSigner(&bytes.Buffer{}, &keypair.Sm2KeyPair{PrivateKey: []byte("bad")}).(*StreamSigner).Error)
	assert.Error(t, NewStreamSigner(&bytes.Buffer{}, &keypair.Sm2KeyPair{}).(*StreamSigner).Error)
	assert.Error(t, NewStreamVerifier(&bytes.Buffer{}, &keypair.Sm2KeyPair{}).(*StreamVerifier).Error)
	assert.Error(t, NewStreamVerifier(&bytes.Buffer{}, &keypair.Sm2KeyPair{PublicKey: []byte("bad")}).(*StreamVerifier).Error)

	errVerifier := &StreamVerifier{Error: errors.New("boom")}
	assert.EqualError(t, errVerifier.Close(), "boom")
}

func TestStreamDecryptBufferReuse(t *testing.T) {
	// cover buffer path when position < len(buffer)
	d := &StreamDecrypter{buffer: []byte("abc")}
	buf := make([]byte, 2)
	n, err := d.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)
	n, err = d.Read(buf)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 1, n)
}

func TestErrorTypes(t *testing.T) {
	errs := []error{
		EncryptError{Err: errors.New("e")},
		DecryptError{Err: errors.New("d")},
		ReadError{Err: errors.New("r")},
		SignError{Err: errors.New("s")},
		VerifyError{Err: errors.New("v")},
	}
	for _, e := range errs {
		assert.NotEmpty(t, e.Error())
	}
}

func TestAdditionalBranches(t *testing.T) {
	kp := mustKeyPair(t)

	// Stream encrypt helper paths
	se := &StreamEncrypter{Error: errors.New("preset")}
	_, err := se.encrypt([]byte("x"))
	assert.EqualError(t, err, "preset")

	se = NewStreamEncrypter(&bytes.Buffer{}, kp).(*StreamEncrypter)
	dst, err := se.encrypt(nil)
	assert.NoError(t, err)
	assert.Nil(t, dst)

	// Stream decrypt helper paths
	sd := &StreamDecrypter{Error: errors.New("preset")}
	_, err = sd.decrypt([]byte("x"))
	assert.EqualError(t, err, "preset")
	sd = NewStreamDecrypter(bytes.NewReader([]byte{0x04}), kp).(*StreamDecrypter)
	out, err := sd.decrypt(nil)
	assert.NoError(t, err)
	assert.Nil(t, out)

	// StdSigner branches
	ss := &StdSigner{Error: errors.New("blocked")}
	_, err = ss.Sign([]byte("x"))
	assert.EqualError(t, err, "blocked")
	ss = &StdSigner{cache: cache{priKey: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: sm2.NewCurve()}, D: big.NewInt(0)}}}
	_, err = ss.Sign([]byte("x"))
	assert.IsType(t, SignError{}, err)

	// StreamSigner Sign error from sm2.Sign
	streamSign := &StreamSigner{
		writer:  &bytes.Buffer{},
		keypair: *kp,
		cache:   cache{priKey: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: sm2.NewCurve()}, D: big.NewInt(0)}},
	}
	streamSign.buffer = []byte("x")
	assert.IsType(t, SignError{}, streamSign.Close())

	closer := mock.NewErrorFile(errors.New("close fail"))
	sv := NewStreamVerifier(closer, kp).(*StreamVerifier)
	assert.EqualError(t, sv.Close(), ReadError{Err: errors.New("close fail")}.Error())
}

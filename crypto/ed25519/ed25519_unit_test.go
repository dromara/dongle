package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func genEd25519KeyPair(t *testing.T) *keypair.Ed25519KeyPair {
	t.Helper()

	kp := keypair.NewEd25519KeyPair()
	require.NoError(t, kp.GenKeyPair())
	return kp
}

func parseEd25519Keys(t *testing.T, kp *keypair.Ed25519KeyPair) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, err := kp.ParsePublicKey()
	require.NoError(t, err)

	pri, err := kp.ParsePrivateKey()
	require.NoError(t, err)

	return pub, pri
}

func TestErrorMessages(t *testing.T) {
	assert.Equal(t, "crypto/ed25519: failed to sign data: boom", SignError{Err: errors.New("boom")}.Error())
	assert.Equal(t, "crypto/ed25519: failed to verify signature: oops", VerifyError{Err: errors.New("oops")}.Error())
	assert.Equal(t, "crypto/ed25519: failed to read data: nope", ReadError{Err: errors.New("nope")}.Error())
}

func TestStdSigner(t *testing.T) {
	t.Run("signs data with valid key", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		pub, _ := parseEd25519Keys(t, kp)

		signer := NewStdSigner(kp)
		require.NoError(t, signer.Error)

		signature, err := signer.Sign([]byte("hello world"))
		require.NoError(t, err)
		assert.True(t, ed25519.Verify(pub, []byte("hello world"), signature))
	})

	t.Run("returns error when private key missing", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		signer := NewStdSigner(kp)

		assert.Error(t, signer.Error)

		_, err := signer.Sign([]byte("data"))
		assert.Error(t, err)

		var signErr SignError
		assert.ErrorAs(t, err, &signErr)
	})

	t.Run("returns error when private key invalid", func(t *testing.T) {
		kp := &keypair.Ed25519KeyPair{PrivateKey: []byte("invalid pem")}
		signer := NewStdSigner(kp)

		assert.Error(t, signer.Error)

		_, err := signer.Sign([]byte("data"))
		assert.Error(t, err)
	})

	t.Run("no signature when data empty", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		signer := NewStdSigner(kp)
		require.NoError(t, signer.Error)

		signature, err := signer.Sign(nil)
		assert.NoError(t, err)
		assert.Nil(t, signature)
	})
}

func TestStreamSigner(t *testing.T) {
	t.Run("write and close with closer succeeds", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		pub, _ := parseEd25519Keys(t, kp)

		buf := &bytes.Buffer{}
		wc := mock.NewWriteCloser(buf)
		signer := NewStreamSigner(wc, kp).(*StreamSigner)
		require.NoError(t, signer.Error)

		n, err := signer.Write([]byte("stream data"))
		require.NoError(t, err)
		assert.Equal(t, len("stream data"), n)

		err = signer.Close()
		require.NoError(t, err)

		assert.NotEmpty(t, buf.Bytes())
		assert.True(t, ed25519.Verify(pub, []byte("stream data"), buf.Bytes()))
	})

	t.Run("close with empty buffer and plain writer", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		buf := &bytes.Buffer{}

		signer := NewStreamSigner(buf, kp).(*StreamSigner)
		require.NoError(t, signer.Error)

		// No Write call; buffer remains empty so sign() returns nil
		err := signer.Close()
		assert.NoError(t, err)
		assert.Equal(t, 0, buf.Len())
	})

	t.Run("propagates write error", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		errWriter := mock.NewErrorWriteCloser(errors.New("write failure"))

		signer := NewStreamSigner(errWriter, kp).(*StreamSigner)
		require.NoError(t, signer.Error)

		_, err := signer.Write([]byte("payload"))
		require.NoError(t, err)

		err = signer.Close()
		assert.EqualError(t, err, "write failure")
	})

	t.Run("propagates close error from writer", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		buf := &bytes.Buffer{}
		closeErr := errors.New("close failure")
		wc := mock.NewCloseErrorWriteCloser(buf, closeErr)

		signer := NewStreamSigner(wc, kp).(*StreamSigner)
		require.NoError(t, signer.Error)

		_, err := signer.Write([]byte("payload"))
		require.NoError(t, err)

		err = signer.Close()
		assert.EqualError(t, err, closeErr.Error())
		assert.NotZero(t, buf.Len())
	})

	t.Run("returns existing error on close and write", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()

		signer := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		assert.Error(t, signer.Error)

		_, writeErr := signer.Write([]byte("data"))
		assert.Equal(t, signer.Error, writeErr)

		closeErr := signer.Close()
		assert.Equal(t, signer.Error, closeErr)
	})

	t.Run("close short-circuits when error preset", func(t *testing.T) {
		w := mock.NewErrorWriteAfterN(1, errors.New("should not write"))
		signer := &StreamSigner{
			writer: w,
			Error:  errors.New("preset"),
		}

		err := signer.Close()
		assert.EqualError(t, err, "preset")
		assert.Equal(t, 0, w.WriteCount())
	})

	t.Run("invalid private key sets error", func(t *testing.T) {
		kp := &keypair.Ed25519KeyPair{PrivateKey: []byte("invalid pem")}
		signer := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		assert.Error(t, signer.Error)
	})

	t.Run("sign returns error when preset error exists", func(t *testing.T) {
		s := &StreamSigner{Error: errors.New("sign blocked")}
		_, err := s.sign([]byte("data"))
		assert.EqualError(t, err, "sign blocked")
	})

	t.Run("sign returns nil signature for empty data", func(t *testing.T) {
		s := &StreamSigner{}
		signature, err := s.sign([]byte{})
		assert.NoError(t, err)
		assert.Nil(t, signature)
	})

	t.Run("write handles empty payload", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		signer := NewStreamSigner(&bytes.Buffer{}, kp).(*StreamSigner)
		require.NoError(t, signer.Error)

		n, err := signer.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write fails when signer has error", func(t *testing.T) {
		signer := &StreamSigner{Error: errors.New("blocked")}
		n, err := signer.Write([]byte("payload"))
		assert.Equal(t, 0, n)
		assert.EqualError(t, err, "blocked")
	})
}

func TestStdVerifier(t *testing.T) {
	t.Run("verifies signature with valid key", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		pub, pri := parseEd25519Keys(t, kp)

		signature := ed25519.Sign(pri, []byte("verify me"))

		verifier := NewStdVerifier(kp)
		require.NoError(t, verifier.Error)

		valid, err := verifier.Verify([]byte("verify me"), signature)
		assert.NoError(t, err)
		assert.True(t, valid)
		assert.Nil(t, verifier.Error)
		assert.True(t, ed25519.Verify(pub, []byte("verify me"), signature))
	})

	t.Run("missing public key yields error", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStdVerifier(kp)
		assert.Error(t, verifier.Error)

		valid, err := verifier.Verify([]byte("data"), []byte("sign"))
		assert.False(t, valid)
		assert.Equal(t, verifier.Error, err)
	})

	t.Run("invalid public key yields error", func(t *testing.T) {
		kp := &keypair.Ed25519KeyPair{PublicKey: []byte("bad pem")}
		verifier := NewStdVerifier(kp)
		assert.Error(t, verifier.Error)

		_, err := verifier.Verify([]byte("data"), []byte("sign"))
		assert.Equal(t, verifier.Error, err)
	})

	t.Run("existing error short circuits", func(t *testing.T) {
		verifier := &StdVerifier{Error: errors.New("already failed")}
		valid, err := verifier.Verify([]byte("data"), []byte("sign"))
		assert.False(t, valid)
		assert.EqualError(t, err, "already failed")
	})

	t.Run("returns no error for empty data", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		verifier := NewStdVerifier(kp)
		require.NoError(t, verifier.Error)

		valid, err := verifier.Verify(nil, []byte("sign"))
		assert.False(t, valid)
		assert.NoError(t, err)
	})

	t.Run("returns error for empty signature", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		verifier := NewStdVerifier(kp)
		require.NoError(t, verifier.Error)

		valid, err := verifier.Verify([]byte("data"), nil)
		assert.False(t, valid)
		assert.Error(t, err)
		var verifyErr VerifyError
		assert.ErrorAs(t, err, &verifyErr)
	})

	t.Run("captures invalid signature", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		verifier := NewStdVerifier(kp)
		require.NoError(t, verifier.Error)

		valid, err := verifier.Verify([]byte("data"), []byte("bad sign"))
		assert.False(t, valid)
		assert.Error(t, err)
		assert.Equal(t, verifier.Error, err)
	})
}

func TestStreamVerifier(t *testing.T) {
	t.Run("stream verification succeeds without closer", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		pub, pri := parseEd25519Keys(t, kp)
		signature := ed25519.Sign(pri, []byte("stream verify"))

		reader := bytes.NewReader(signature)
		verifier := NewStreamVerifier(reader, kp).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		n, err := verifier.Write([]byte("stream verify"))
		require.NoError(t, err)
		assert.Equal(t, len("stream verify"), n)

		err = verifier.Close()
		assert.NoError(t, err)
		assert.True(t, verifier.verified)
		assert.True(t, ed25519.Verify(pub, []byte("stream verify"), signature))
	})

	t.Run("stream verification closes reader with error", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		_, pri := parseEd25519Keys(t, kp)
		signature := ed25519.Sign(pri, []byte("stream close error"))

		reader := mock.NewCloseErrorReadCloser(bytes.NewReader(signature), errors.New("close error"))
		verifier := NewStreamVerifier(reader, kp).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		_, err := verifier.Write([]byte("stream close error"))
		require.NoError(t, err)

		err = verifier.Close()
		assert.EqualError(t, err, "close error")
		assert.True(t, verifier.verified)
	})

	t.Run("returns error when public key missing", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStreamVerifier(bytes.NewReader(nil), kp).(*StreamVerifier)
		assert.Error(t, verifier.Error)

		_, err := verifier.Write([]byte("data"))
		assert.Equal(t, verifier.Error, err)

		closeErr := verifier.Close()
		assert.Equal(t, verifier.Error, closeErr)
	})

	t.Run("returns error when public key invalid", func(t *testing.T) {
		kp := &keypair.Ed25519KeyPair{PublicKey: []byte("invalid pem")}
		verifier := NewStreamVerifier(bytes.NewReader(nil), kp).(*StreamVerifier)
		assert.Error(t, verifier.Error)
	})

	t.Run("close returns read error", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		reader := mock.NewErrorFile(errors.New("read failure"))

		verifier := NewStreamVerifier(reader, kp).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		err := verifier.Close()
		var readErr ReadError
		assert.ErrorAs(t, err, &readErr)
	})

	t.Run("close returns nil when signature empty", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		reader := bytes.NewReader(nil)
		verifier := NewStreamVerifier(reader, kp).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		_, err := verifier.Write([]byte("data"))
		require.NoError(t, err)

		err = verifier.Close()
		assert.NoError(t, err)
		assert.False(t, verifier.verified)
	})

	t.Run("close verifies with empty data buffer", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		_, pri := parseEd25519Keys(t, kp)
		signature := ed25519.Sign(pri, []byte("bufferless"))

		verifier := NewStreamVerifier(bytes.NewReader(signature), kp).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		err := verifier.Close()
		assert.NoError(t, err)
		assert.False(t, verifier.verified)
	})

	t.Run("close returns verify error for invalid signature", func(t *testing.T) {
		kpGood := genEd25519KeyPair(t)
		kpBad := genEd25519KeyPair(t)
		_, badPri := parseEd25519Keys(t, kpBad)

		signature := ed25519.Sign(badPri, []byte("data"))
		verifier := NewStreamVerifier(bytes.NewReader(signature), kpGood).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		_, err := verifier.Write([]byte("data"))
		require.NoError(t, err)

		err = verifier.Close()
		assert.Error(t, err)
		assert.Equal(t, verifier.Error, err)
		assert.False(t, verifier.verified)
	})

	t.Run("write handles empty payload", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		verifier := NewStreamVerifier(bytes.NewReader(nil), kp).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		n, err := verifier.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write fails when verifier has error", func(t *testing.T) {
		verifier := &StreamVerifier{Error: errors.New("blocked")}
		n, err := verifier.Write([]byte("payload"))
		assert.Equal(t, 0, n)
		assert.EqualError(t, err, "blocked")
	})

	t.Run("verify handles preset error and empty values", func(t *testing.T) {
		verifier := &StreamVerifier{Error: errors.New("existing")}
		_, err := verifier.verify([]byte("data"), []byte("sign"))
		assert.EqualError(t, err, "existing")

		verifier.Error = nil
		valid, err := verifier.verify([]byte{}, []byte("sign"))
		assert.False(t, valid)
		assert.NoError(t, err)

		valid, err = verifier.verify([]byte("data"), []byte{})
		assert.False(t, valid)
		assert.Error(t, err)
	})

	t.Run("verify detects invalid and valid signatures", func(t *testing.T) {
		kp := genEd25519KeyPair(t)
		pub, pri := parseEd25519Keys(t, kp)
		data := []byte("payload")
		signature := ed25519.Sign(pri, data)

		verifier := NewStreamVerifier(bytes.NewReader(nil), kp).(*StreamVerifier)
		require.NoError(t, verifier.Error)

		valid, err := verifier.verify(data, []byte("bad sign"))
		assert.False(t, valid)
		assert.Equal(t, verifier.Error, err)

		verifier.Error = nil
		valid, err = verifier.verify(data, signature)
		assert.True(t, valid)
		assert.NoError(t, err)
		assert.True(t, ed25519.Verify(pub, data, signature))
	})
}

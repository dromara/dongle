package ed25519

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestNewStdSigner(t *testing.T) {
	t.Run("create new standard signer with empty key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		signer := NewStdSigner(kp)
		assert.NotNil(t, signer)
		assert.NotNil(t, signer.Error)

		var signErr SignError
		assert.True(t, errors.As(signer.Error, &signErr))

		var emptyPrivateKeyErr keypair.EmptyPrivateKeyError
		assert.True(t, errors.As(signErr.Err, &emptyPrivateKeyErr))
	})

	t.Run("create new standard signer with valid key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		assert.NotNil(t, signer)
		assert.Nil(t, signer.Error)
	})
}

func TestNewStdVerifier(t *testing.T) {
	t.Run("create new standard verifier with empty key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier)
		assert.NotNil(t, verifier.Error)

		var verifyErr VerifyError
		assert.True(t, errors.As(verifier.Error, &verifyErr))

		var emptyPublicKeyErr keypair.EmptyPublicKeyError
		assert.True(t, errors.As(verifyErr.Err, &emptyPublicKeyErr))
	})

	t.Run("create new standard verifier with valid key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier)
		assert.Nil(t, verifier.Error)
	})
}

func TestStdSignerSign(t *testing.T) {
	t.Run("sign with empty private key error", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("sign with empty data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte{})
		assert.Nil(t, signature)
		assert.Nil(t, err)
	})

	t.Run("sign with valid data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)
		assert.NotEmpty(t, signature)
	})

	t.Run("sign with invalid private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)

		var signErr SignError
		assert.True(t, errors.As(err, &signErr))
	})

	t.Run("sign with invalid formatted private key content", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		_ = kp.SetPrivateKey([]byte("aGVsbG8="))

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("sign with large data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		signature, err := signer.Sign(largeData)
		assert.Nil(t, err)
		assert.NotNil(t, signature)
		assert.NotEmpty(t, signature)
	})

	t.Run("sign with corrupted private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
invalid base64 content
-----END PRIVATE KEY-----`))

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)

		var signErr SignError
		assert.True(t, errors.As(err, &signErr))
	})
}

func TestStdVerifierVerify(t *testing.T) {
	t.Run("verify with empty public key error", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with empty data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte{}, []byte("some signature"))
		assert.False(t, valid)
		assert.Nil(t, err)
	})

	t.Run("verify with empty signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte{})
		assert.False(t, valid)
		assert.NotNil(t, err)

		var verifyErr VerifyError
		assert.True(t, errors.As(err, &verifyErr))

		var emptySignatureErr keypair.EmptySignatureError
		assert.True(t, errors.As(verifyErr.Err, &emptySignatureErr))
	})

	t.Run("verify with valid data and signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), signature)
		assert.True(t, valid)
		assert.Nil(t, err)
	})

	t.Run("verify with invalid signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte("invalid signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)

		var verifyErr VerifyError
		assert.True(t, errors.As(err, &verifyErr))
	})

	t.Run("verify with invalid public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPublicKey([]byte("invalid public key"))

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)

		var verifyErr VerifyError
		assert.True(t, errors.As(err, &verifyErr))
	})

	t.Run("verify with large data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		signature, err := signer.Sign(largeData)
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify(largeData, signature)
		assert.True(t, valid)
		assert.Nil(t, err)
	})

	t.Run("verify with corrupted public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		kp.PublicKey = []byte("-----BEGIN PUBLIC KEY-----\ninvalid base64 content\n-----END PUBLIC KEY-----")

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), signature)
		assert.False(t, valid)
		assert.NotNil(t, err)

		var verifyErr VerifyError
		assert.True(t, errors.As(err, &verifyErr))
	})
}

func TestNewStreamSigner(t *testing.T) {
	t.Run("create new stream signer with empty key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		signer := NewStreamSigner(&buf, kp)
		assert.NotNil(t, signer)
	})

	t.Run("create new stream signer with valid key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		assert.NotNil(t, signer)
	})
}

func TestStreamSignerWrite(t *testing.T) {
	t.Run("write with empty data", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		n, err := signer.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("write with valid data", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		n, err := signer.Write([]byte("test data"))
		assert.Equal(t, 9, n)
		assert.Nil(t, err)
	})
}

func TestStreamSignerClose(t *testing.T) {
	t.Run("close with valid data", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("close with empty key pair error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		signer := NewStreamSigner(&buf, kp)
		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("close with empty data and writer implements Closer", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "sig.bin")
		defer file.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(file, kp)
		err := signer.Close()
		assert.Nil(t, err)
	})

	t.Run("close with writer that writes ok but close fails", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		wc := mock.NewCloseErrorWriteCloser(&buf, assert.AnError)
		signer := NewStreamSigner(wc, kp)
		_, _ = signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
	})

	t.Run("close with empty data and close fails", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		wc := mock.NewCloseErrorWriteCloser(&buf, assert.AnError)
		signer := NewStreamSigner(wc, kp)
		err := signer.Close()
		assert.NotNil(t, err)
	})

	t.Run("close with invalid private key", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))

		signer := NewStreamSigner(&buf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)

		var signErr SignError
		assert.True(t, errors.As(err, &signErr))
	})

	t.Run("close with write error", func(t *testing.T) {
		errorWriter := mock.NewErrorFile(assert.AnError)
		defer errorWriter.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(errorWriter, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
	})

	t.Run("close with sign error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		_ = kp.SetPrivateKey([]byte("aGVsbG8="))

		signer := NewStreamSigner(&buf, kp)
		_, _ = signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})
}

func TestStreamSignerSign(t *testing.T) {
	t.Run("sign with invalid private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))

		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)
		signature, err := streamSigner.sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})
}

func TestNewStreamVerifier(t *testing.T) {
	t.Run("create new stream verifier with empty key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStreamVerifier(&buf, kp)
		assert.NotNil(t, verifier)
	})

	t.Run("create new stream verifier with valid key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&buf, kp)
		assert.NotNil(t, verifier)
	})
}

func TestStreamVerifierWrite(t *testing.T) {
	t.Run("write with empty data", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&buf, kp)
		n, err := verifier.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("write with valid data", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&buf, kp)
		n, err := verifier.Write([]byte("test data"))
		assert.Equal(t, 9, n)
		assert.Nil(t, err)
	})
}

func TestStreamVerifierClose(t *testing.T) {
	t.Run("close with valid data and signature", func(t *testing.T) {
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		var verifyBuf bytes.Buffer
		verifyBuf.Write(signature)
		verifier := NewStreamVerifier(&verifyBuf, kp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.Nil(t, err)
	})

	t.Run("close with invalid public key", func(t *testing.T) {
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		var verifyBuf bytes.Buffer
		verifyBuf.Write(signature)
		invalidKp := keypair.NewEd25519KeyPair()
		invalidKp.SetPublicKey([]byte("invalid public key"))
		verifier := NewStreamVerifier(&verifyBuf, invalidKp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.NotNil(t, err)

		var verifyErr VerifyError
		assert.True(t, errors.As(err, &verifyErr))
	})

	t.Run("close with read error", func(t *testing.T) {
		errorReader := mock.NewErrorFile(assert.AnError)
		defer errorReader.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(errorReader, kp)
		verifier.Write([]byte("test data"))
		err := verifier.Close()
		assert.NotNil(t, err)

		var readErr ReadError
		assert.True(t, errors.As(err, &readErr))
	})

	t.Run("close with verify error", func(t *testing.T) {
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		var verifyBuf bytes.Buffer
		verifyBuf.Write(signature)
		verifier := NewStreamVerifier(&verifyBuf, kp)
		verifier.Write([]byte("wrong data"))
		err = verifier.Close()
		assert.NotNil(t, err)

		var verifyErr VerifyError
		assert.True(t, errors.As(err, &verifyErr))
	})

	t.Run("close with initialization error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStreamVerifier(&buf, kp)
		err := verifier.Close()
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("close with reader that implements Closer", func(t *testing.T) {
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		file := mock.NewFile(signature, "signature.txt")
		defer file.Close()

		verifier := NewStreamVerifier(file, kp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.Nil(t, err)
	})

	t.Run("close with reader that implements Closer and returns error", func(t *testing.T) {
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		errorFile := mock.NewErrorFile(assert.AnError)
		defer errorFile.Close()

		_, _ = errorFile.Write(signature)

		verifier := NewStreamVerifier(errorFile, kp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.NotNil(t, err)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("close with empty signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		var verifyBuf bytes.Buffer
		verifier := NewStreamVerifier(&verifyBuf, kp)
		verifier.Write([]byte("test data"))
		err := verifier.Close()
		assert.Nil(t, err)
	})
}

func TestStreamVerifierVerify(t *testing.T) {
	t.Run("verify with invalid public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPublicKey([]byte("invalid public key"))

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with invalid signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.verify([]byte("test data"), []byte("invalid signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with valid signature but wrong data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("original data"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.verify([]byte("different data"), signature)
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with empty data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.verify([]byte{}, []byte("signature"))
		assert.False(t, valid)
		assert.Nil(t, err)
	})

	t.Run("verify with empty signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.verify([]byte("test data"), []byte{})
		assert.False(t, valid)
		assert.Nil(t, err)
	})
}

func TestStreamVerifierWriteEdgeCases(t *testing.T) {
	t.Run("write with buffer growth", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		largeData := make([]byte, 1000)
		n, err := verifier.Write(largeData)
		assert.Nil(t, err)
		assert.Equal(t, 1000, n)
		assert.Equal(t, 1000, len(streamVerifier.buffer))

		moreData := make([]byte, 2000)
		n, err = verifier.Write(moreData)
		assert.Nil(t, err)
		assert.Equal(t, 2000, n)
		assert.Equal(t, 3000, len(streamVerifier.buffer))
	})

	t.Run("write with initialization error", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)

		data := []byte("test data")
		n, err := verifier.Write(data)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("write with nil data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		n, err := verifier.Write(nil)
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 0, len(streamVerifier.buffer))
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("SignError", func(t *testing.T) {
		innerErr := keypair.EmptyPrivateKeyError{}
		err := SignError{Err: innerErr}

		_ = err.Error()

		var signErr SignError
		assert.True(t, errors.As(err, &signErr))

		var emptyPrivateKeyErr keypair.EmptyPrivateKeyError
		assert.True(t, errors.As(signErr.Err, &emptyPrivateKeyErr))
	})

	t.Run("VerifyError", func(t *testing.T) {
		innerErr := keypair.EmptyPublicKeyError{}
		err := VerifyError{Err: innerErr}

		_ = err.Error()

		var verifyErr VerifyError
		assert.True(t, errors.As(err, &verifyErr))

		var emptyPublicKeyErr keypair.EmptyPublicKeyError
		assert.True(t, errors.As(verifyErr.Err, &emptyPublicKeyErr))
	})

	t.Run("ReadError", func(t *testing.T) {
		innerErr := assert.AnError
		err := ReadError{Err: innerErr}

		_ = err.Error()

		var readErr ReadError
		assert.True(t, errors.As(err, &readErr))
		assert.Equal(t, innerErr, readErr.Err)
	})
}

func TestStreamSignerWriteBufferGrowth(t *testing.T) {
	t.Run("write with buffer capacity expansion", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		initialData := make([]byte, 100)
		n, err := signer.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)

		expansionData := make([]byte, 50)
		n, err = signer.Write(expansionData)
		assert.Nil(t, err)
		assert.Equal(t, 50, n)
		assert.Equal(t, 150, len(streamSigner.buffer))
		assert.True(t, cap(streamSigner.buffer) >= 150)
	})

	t.Run("write with large buffer expansion", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		initialData := make([]byte, 100)
		n, err := signer.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)

		largeExpansionData := make([]byte, 150)
		n, err = signer.Write(largeExpansionData)
		assert.Nil(t, err)
		assert.Equal(t, 150, n)
		assert.Equal(t, 250, len(streamSigner.buffer))
		assert.True(t, cap(streamSigner.buffer) >= 250)
	})
}

func TestStreamSignerWriteEdgeCases(t *testing.T) {
	t.Run("write with initialization error", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		signer := NewStreamSigner(&buf, kp)

		data := []byte("test data")
		n, err := signer.Write(data)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, SignError{}, err)
	})

	t.Run("write with nil data", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		n, err := signer.Write(nil)
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestCloseWithoutWriterCloser(t *testing.T) {
	t.Run("close with writer that does NOT implement io.Closer", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		_, _ = signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		assert.NotEmpty(t, buf.Bytes())
	})
}

func TestNewStreamVerifierWithValidKeyPair(t *testing.T) {
	t.Run("create stream verifier with valid key pair and successful parsing", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&buf, kp)
		assert.NotNil(t, verifier)

		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		assert.NotNil(t, streamVerifier.pubKey)
		assert.Nil(t, streamVerifier.Error)
	})

	t.Run("create stream verifier with invalid public key that fails parsing", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
invalid base64 content
-----END PUBLIC KEY-----`)

		verifier := NewStreamVerifier(&buf, kp)
		assert.NotNil(t, verifier)

		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		assert.NotNil(t, streamVerifier.Error)
		assert.IsType(t, VerifyError{}, streamVerifier.Error)
	})
}

func TestStreamSignerCloseWithSignError(t *testing.T) {
	t.Run("close when Sign returns error due to nil private key", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		streamSigner.priKey = nil

		_, _ = signer.Write([]byte("test data"))

		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, SignError{}, err)
	})
}

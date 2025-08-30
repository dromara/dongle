package ed25519

import (
	"bytes"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestNewStdSigner tests the NewStdSigner function
func TestNewStdSigner(t *testing.T) {
	t.Run("create new standard signer with nil key pair", func(t *testing.T) {
		signer := NewStdSigner(nil)
		assert.NotNil(t, signer)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, NilKeyPairError{}, signer.Error)
	})

	t.Run("create new standard signer with empty key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		signer := NewStdSigner(kp)
		assert.NotNil(t, signer)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, KeyPairError{}, signer.Error)
		// Check that the error message contains the expected text
		assert.Contains(t, signer.Error.Error(), "invalid key pair")
	})

	t.Run("create new standard signer with valid key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		assert.NotNil(t, signer)
		assert.Nil(t, signer.Error)
	})

	// Test with key pair that has empty private key
	t.Run("create new standard signer with empty private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		signer := NewStdSigner(kp)
		assert.NotNil(t, signer)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, KeyPairError{}, signer.Error)
		// Check that the error message contains the expected text
		assert.Contains(t, signer.Error.Error(), "invalid key pair")
	})
}

// TestNewStdVerifier tests the NewStdVerifier function
func TestNewStdVerifier(t *testing.T) {
	t.Run("create new standard verifier with nil key pair", func(t *testing.T) {
		verifier := NewStdVerifier(nil)
		assert.NotNil(t, verifier)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, NilKeyPairError{}, verifier.Error)
	})

	t.Run("create new standard verifier with empty key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, KeyPairError{}, verifier.Error)
		// Check that the error message contains the expected text
		assert.Contains(t, verifier.Error.Error(), "invalid key pair")
	})

	t.Run("create new standard verifier with valid key pair", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier)
		assert.Nil(t, verifier.Error)
	})

	// Test with key pair that has empty public key
	t.Run("create new standard verifier with empty public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStdVerifier(kp)
		assert.NotNil(t, verifier)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, KeyPairError{}, verifier.Error)
		// Check that the error message contains the expected text
		assert.Contains(t, verifier.Error.Error(), "invalid key pair")
	})
}

// TestStdSignerSign tests the Sign method of StdSigner
func TestStdSignerSign(t *testing.T) {
	t.Run("sign with nil key pair error", func(t *testing.T) {
		signer := NewStdSigner(nil)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, NilKeyPairError{}, err)
	})

	t.Run("sign with empty data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte{})
		assert.Nil(t, signature) // ED25519 rejects empty data
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

	// Test error path when parsing private key fails
	t.Run("sign with invalid private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})

	// Test error path when private key is nil
	t.Run("sign with nil private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})

	// Test error path when signer has initialization error
	t.Run("sign with initialization error", func(t *testing.T) {
		signer := NewStdSigner(nil)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, NilKeyPairError{}, err)
	})

	// Test sign with empty data
	t.Run("sign with empty data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte{})
		assert.Nil(t, signature) // ED25519 rejects empty data
		assert.Nil(t, err)
	})

	// Test sign with very large data
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

	// Test sign with corrupted private key that causes ParsePrivateKey to return an error
	t.Run("sign with corrupted private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		// Create a corrupted private key that will cause ParsePrivateKey to return an error
		kp.SetPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
invalid base64 content
-----END PRIVATE KEY-----`))

		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})
}

// TestStdVerifierVerify tests the Verify method of StdVerifier
func TestStdVerifierVerify(t *testing.T) {
	t.Run("verify with nil key pair error", func(t *testing.T) {
		verifier := NewStdVerifier(nil)
		valid, err := verifier.Verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, NilKeyPairError{}, err)
	})

	t.Run("verify with empty data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		// Try to verify empty data - should return false, nil
		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte{}, []byte("some signature"))
		assert.False(t, valid) // Should be false
		assert.Nil(t, err)
	})

	t.Run("verify with empty signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte{})
		assert.False(t, valid)
		assert.Nil(t, err) // Should return nil, not error for empty signature
	})

	t.Run("verify with valid data and signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		// First sign the data
		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		// Then verify the signature
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
		assert.IsType(t, VerifyError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "verify error")
	})

	// Test error path when parsing public key fails
	t.Run("verify with invalid public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPublicKey([]byte("invalid public key"))

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})

	// Test error path when public key is nil
	t.Run("verify with nil public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})

	// Test error path when verifier has initialization error
	t.Run("verify with initialization error", func(t *testing.T) {
		verifier := NewStdVerifier(nil)
		valid, err := verifier.Verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, NilKeyPairError{}, err)
	})

	// Test verify with empty data
	t.Run("verify with empty data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		// Try to verify empty data - should return false, nil
		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte{}, []byte("some signature"))
		assert.False(t, valid) // Should be false
		assert.Nil(t, err)
	})

	// Test verify with empty signature
	t.Run("verify with empty signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte{})
		assert.False(t, valid)
		assert.Nil(t, err) // Should return nil, not error for empty signature
	})

	// Test verify with invalid signature (verification fails)
	t.Run("verify with invalid signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), []byte("invalid signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "verify error")
	})

	// Test verify with very large data
	t.Run("verify with large data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		// First sign the data
		signer := NewStdSigner(kp)
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		signature, err := signer.Sign(largeData)
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		// Then verify the signature
		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify(largeData, signature)
		assert.True(t, valid)
		assert.Nil(t, err)
	})

	// Test verify with corrupted public key that causes ParsePublicKey to return an error
	t.Run("verify with corrupted public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		// First sign the data
		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("test data"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		// Create a corrupted public key that will cause ParsePublicKey to return an error
		kp.SetPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
invalid base64 content
-----END PUBLIC KEY-----`))

		verifier := NewStdVerifier(kp)
		valid, err := verifier.Verify([]byte("test data"), signature)
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})
}

// TestNewStreamSigner tests the NewStreamSigner function
func TestNewStreamSigner(t *testing.T) {
	t.Run("create new stream signer with nil key pair", func(t *testing.T) {
		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, nil)
		assert.NotNil(t, signer)
		// We can't directly access Error field because signer is io.WriteCloser
	})

	t.Run("create new stream signer with empty key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		signer := NewStreamSigner(&buf, kp)
		assert.NotNil(t, signer)
		// We can't directly access Error field because signer is io.WriteCloser
	})

	t.Run("create new stream signer with valid key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		assert.NotNil(t, signer)
		// We can't directly access Error field because signer is io.WriteCloser
	})
}

// TestStreamSignerWrite tests the Write method of StreamSigner
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

// TestStreamSignerClose tests the Close method of StreamSigner
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

	// Test error path when parsing private key fails
	t.Run("close with invalid private key", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))

		signer := NewStreamSigner(&buf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})

	// Test error path when writing to writer fails
	t.Run("close with write error", func(t *testing.T) {
		// Create a mock writer that returns an error
		errorWriter := mock.NewErrorFile(assert.AnError)
		defer errorWriter.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(errorWriter, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
	})

	// Test error path when signer has initialization error
	t.Run("close with initialization error", func(t *testing.T) {
		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, nil)
		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, NilKeyPairError{}, err)
	})

	// Test successful close with writer that implements io.Closer
	t.Run("close with writer that implements Closer", func(t *testing.T) {
		// Create a mock file that implements io.Closer
		file := mock.NewFile([]byte{}, "test.txt")
		defer file.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(file, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
	})

	// Test close with writer that implements io.Closer and returns an error
	t.Run("close with writer that implements Closer and returns error", func(t *testing.T) {
		// Create a mock file that implements io.Closer and returns an error
		errorFile := mock.NewErrorFile(assert.AnError)
		defer errorFile.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(errorFile, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
	})

	// Test close with empty data
	t.Run("close with empty data", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		err := signer.Close()
		assert.Nil(t, err)
	})

	// Test close with writer that implements io.Closer and closes successfully
	t.Run("close with writer that implements Closer and closes successfully", func(t *testing.T) {
		// Create a mock file that implements io.Closer and closes successfully
		file := mock.NewFile([]byte{}, "test.txt")
		defer file.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(file, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
	})

	// Test close with writer that implements io.Closer but closing fails
	t.Run("close with writer that implements Closer but closing fails", func(t *testing.T) {
		// Create a mock file that implements io.Closer but closing fails
		errorFile := mock.NewErrorFile(assert.AnError)
		defer errorFile.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(errorFile, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
	})

	// Test close with sign error (when Sign method returns an error)
	t.Run("close with sign error", func(t *testing.T) {
		// Create a mock writer that works correctly
		var buf bytes.Buffer

		// Create a keypair with invalid private key to cause Sign to return an error
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))

		signer := NewStreamSigner(&buf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
	})

	// Test close with sign error that directly tests the error return path
	t.Run("close with sign error directly testing error return", func(t *testing.T) {
		// Create a mock writer that works correctly
		var buf bytes.Buffer

		// Create a keypair with invalid private key to cause Sign to return an error
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
invalid base64 content
-----END PRIVATE KEY-----`))

		signer := NewStreamSigner(&buf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
	})

	// Test close with write error after successful sign
	t.Run("close with write error after successful sign", func(t *testing.T) {
		// Create a mock writer that returns an error on Write
		errorWriter := mock.NewErrorFile(assert.AnError)
		defer errorWriter.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(errorWriter, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
	})

	// Test close with writer that implements io.Closer and closes with nil error
	t.Run("close with writer that implements Closer and closes with nil error", func(t *testing.T) {
		// Create a mock file that implements io.Closer and closes with nil error
		file := mock.NewFile([]byte{}, "test.txt")
		defer file.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(file, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
	})

	// Test close with writer that implements io.Closer but Close() returns an error
	t.Run("close with writer that implements Closer but Close() returns error", func(t *testing.T) {
		// Create a mock file that implements io.Closer but Close() returns an error
		errorFile := mock.NewErrorFile(assert.AnError)
		defer errorFile.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(errorFile, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.NotNil(t, err)
	})
}

// TestStreamSignerSign tests the Sign method of StreamSigner
func TestStreamSignerSign(t *testing.T) {
	t.Run("sign with invalid private key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPrivateKey([]byte("invalid private key"))

		signer := NewStreamSigner(&bytes.Buffer{}, kp)
		// We need to cast to access the Sign method
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)
		signature, err := streamSigner.Sign([]byte("test data"))
		assert.Nil(t, signature)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
	})
}

// TestNewStreamVerifier tests the NewStreamVerifier function
func TestNewStreamVerifier(t *testing.T) {
	t.Run("create new stream verifier with nil key pair", func(t *testing.T) {
		var buf bytes.Buffer
		verifier := NewStreamVerifier(&buf, nil)
		assert.NotNil(t, verifier)
		// We can't directly access Error field because verifier is io.WriteCloser
	})

	t.Run("create new stream verifier with empty key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		verifier := NewStreamVerifier(&buf, kp)
		assert.NotNil(t, verifier)
		// We can't directly access Error field because verifier is io.WriteCloser
	})

	t.Run("create new stream verifier with valid key pair", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&buf, kp)
		assert.NotNil(t, verifier)
		// We can't directly access Error field because verifier is io.WriteCloser
	})
}

// TestStreamVerifierWrite tests the Write method of StreamVerifier
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

// TestStreamVerifierClose tests the Close method of StreamVerifier
func TestStreamVerifierClose(t *testing.T) {
	t.Run("close with valid data and signature", func(t *testing.T) {
		// First create a signature
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		// Then verify the signature
		var verifyBuf bytes.Buffer
		verifyBuf.Write(signature)
		verifier := NewStreamVerifier(&verifyBuf, kp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.Nil(t, err)
	})

	// Test error path when parsing public key fails
	t.Run("close with invalid public key", func(t *testing.T) {
		// First create a signature
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		// Then try to verify with invalid public key
		var verifyBuf bytes.Buffer
		verifyBuf.Write(signature)
		invalidKp := keypair.NewEd25519KeyPair()
		invalidKp.SetPublicKey([]byte("invalid public key"))
		verifier := NewStreamVerifier(&verifyBuf, invalidKp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "invalid key pair")
	})

	// Test error path when reading signature fails
	t.Run("close with read error", func(t *testing.T) {
		// Create a mock reader that returns an error
		errorReader := mock.NewErrorFile(assert.AnError)
		defer errorReader.Close()

		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(errorReader, kp)
		verifier.Write([]byte("test data"))
		err := verifier.Close()
		assert.NotNil(t, err)
		assert.IsType(t, ReadError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "read error")
	})

	// Test error path when verifying signature fails
	t.Run("close with verify error", func(t *testing.T) {
		// First create a signature
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		// Then try to verify with wrong data
		var verifyBuf bytes.Buffer
		verifyBuf.Write(signature)
		verifier := NewStreamVerifier(&verifyBuf, kp)
		verifier.Write([]byte("wrong data"))
		err = verifier.Close()
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
		// Check that the error message contains the expected text
		assert.Contains(t, err.Error(), "verify error")
	})

	// Test error path when verifier has initialization error
	t.Run("close with initialization error", func(t *testing.T) {
		var buf bytes.Buffer
		verifier := NewStreamVerifier(&buf, nil)
		err := verifier.Close()
		assert.NotNil(t, err)
		assert.IsType(t, NilKeyPairError{}, err)
	})

	// Test successful close with reader that implements io.Closer
	t.Run("close with reader that implements Closer", func(t *testing.T) {
		// First create a signature
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		// Then verify the signature with a reader that implements io.Closer
		file := mock.NewFile(signature, "signature.txt")
		defer file.Close()

		verifier := NewStreamVerifier(file, kp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.Nil(t, err)
	})

	// Test close with reader that implements io.Closer and returns an error
	t.Run("close with reader that implements Closer and returns error", func(t *testing.T) {
		// First create a signature
		var signBuf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&signBuf, kp)
		signer.Write([]byte("test data"))
		err := signer.Close()
		assert.Nil(t, err)
		signature := signBuf.Bytes()

		// Then verify the signature with a reader that implements io.Closer and returns an error
		errorFile := mock.NewErrorFile(assert.AnError)
		defer errorFile.Close()

		// First write the signature to the error file
		_, _ = errorFile.Write(signature)

		verifier := NewStreamVerifier(errorFile, kp)
		verifier.Write([]byte("test data"))
		err = verifier.Close()
		assert.NotNil(t, err)
	})

	// Test close with empty signature
	t.Run("close with empty signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		// Verify with empty signature
		var verifyBuf bytes.Buffer
		verifier := NewStreamVerifier(&verifyBuf, kp)
		verifier.Write([]byte("test data"))
		err := verifier.Close()
		assert.Nil(t, err)
	})
}

// TestStreamVerifierVerify tests the Verify method of StreamVerifier
func TestStreamVerifierVerify(t *testing.T) {
	t.Run("verify with invalid public key", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.SetPublicKey([]byte("invalid public key"))

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		// We need to cast to access the Verify method
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.Verify([]byte("test data"), []byte("signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, KeyPairError{}, err)
	})

	t.Run("verify with invalid signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		// We need to cast to access the Verify method
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.Verify([]byte("test data"), []byte("invalid signature"))
		assert.False(t, valid)
		assert.NotNil(t, err)
		assert.IsType(t, VerifyError{}, err)
	})

	t.Run("verify with valid signature but wrong data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		// First sign some data to get a valid signature
		signer := NewStdSigner(kp)
		signature, err := signer.Sign([]byte("original data"))
		assert.Nil(t, err)
		assert.NotNil(t, signature)

		// Then try to verify different data with that signature
		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.Verify([]byte("different data"), signature)
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
		valid, err := streamVerifier.Verify([]byte{}, []byte("signature"))
		assert.False(t, valid)
		assert.Nil(t, err) // Should return nil for empty data
	})

	t.Run("verify with empty signature", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)
		valid, err := streamVerifier.Verify([]byte("test data"), []byte{})
		assert.False(t, valid)
		assert.Nil(t, err) // Should return nil for empty signature
	})
}

// TestStreamVerifierWriteEdgeCases tests edge cases for StreamVerifier Write method
func TestStreamVerifierWriteEdgeCases(t *testing.T) {
	t.Run("write with buffer growth", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		// Write data that will trigger buffer growth
		largeData := make([]byte, 1000)
		n, err := verifier.Write(largeData)
		assert.Nil(t, err)
		assert.Equal(t, 1000, n)
		assert.Equal(t, 1000, len(streamVerifier.buffer))

		// Write more data to trigger another buffer growth
		moreData := make([]byte, 2000)
		n, err = verifier.Write(moreData)
		assert.Nil(t, err)
		assert.Equal(t, 2000, n)
		assert.Equal(t, 3000, len(streamVerifier.buffer))
	})

	t.Run("write with exact buffer capacity", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		// Write data that exactly fits the current buffer capacity
		initialData := make([]byte, 100)
		n, err := verifier.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)

		// Write data that requires exact capacity expansion
		exactFitData := make([]byte, 100)
		n, err = verifier.Write(exactFitData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)
		assert.Equal(t, 200, len(streamVerifier.buffer))
	})

	t.Run("write with buffer growth edge case", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		// Write data to create a specific buffer state
		initialData := make([]byte, 10)
		n, err := verifier.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 10, n)

		// Write data that triggers the 2*cap condition
		triggerData := make([]byte, 15)
		n, err = verifier.Write(triggerData)
		assert.Nil(t, err)
		assert.Equal(t, 15, n)
		assert.Equal(t, 25, len(streamVerifier.buffer))
	})

	t.Run("write with initialization error", func(t *testing.T) {
		// Create a verifier with initialization error
		verifier := NewStreamVerifier(&bytes.Buffer{}, nil)

		// Try to write data - should return error immediately
		data := []byte("test data")
		n, err := verifier.Write(data)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, NilKeyPairError{}, err)
	})

	t.Run("write with empty data multiple times", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		// Write empty data multiple times
		for i := 0; i < 5; i++ {
			n, err := verifier.Write([]byte{})
			assert.Nil(t, err)
			assert.Equal(t, 0, n)
		}

		// Buffer should remain empty
		assert.Equal(t, 0, len(streamVerifier.buffer))
	})

	t.Run("write with nil data", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		// Write nil data
		n, err := verifier.Write(nil)
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 0, len(streamVerifier.buffer))
	})

	t.Run("write with sufficient buffer capacity", func(t *testing.T) {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		verifier := NewStreamVerifier(&bytes.Buffer{}, kp)
		streamVerifier, ok := verifier.(*StreamVerifier)
		assert.True(t, ok)

		// Write initial data to create buffer
		initialData := make([]byte, 100)
		n, err := verifier.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)

		// Write small data that fits within existing capacity
		smallData := make([]byte, 50)
		n, err = verifier.Write(smallData)
		assert.Nil(t, err)
		assert.Equal(t, 50, n)
		assert.Equal(t, 150, len(streamVerifier.buffer))

		// Write more small data that still fits
		moreSmallData := make([]byte, 25)
		n, err = verifier.Write(moreSmallData)
		assert.Nil(t, err)
		assert.Equal(t, 25, n)
		assert.Equal(t, 175, len(streamVerifier.buffer))
	})
}

// TestErrorTypes tests all error types to achieve 100% coverage
func TestErrorTypes(t *testing.T) {
	t.Run("NilKeyPairError", func(t *testing.T) {
		err := NilKeyPairError{}
		expected := "key pair cannot be nil"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("PublicKeyUnsetError", func(t *testing.T) {
		err := PublicKeyUnsetError{}
		expected := "public key not set, please use SetPublicKey() method"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("PrivateKeyUnsetError", func(t *testing.T) {
		err := PrivateKeyUnsetError{}
		expected := "private key not set, please use SetPrivateKey() method"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("KeyPairError", func(t *testing.T) {
		err := KeyPairError{Err: assert.AnError}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "invalid key pair")
	})

	t.Run("KeyPairError with nil", func(t *testing.T) {
		err := KeyPairError{Err: nil}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "invalid key pair")
	})

	t.Run("SignError", func(t *testing.T) {
		err := SignError{Err: assert.AnError}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "sign error")
	})

	t.Run("SignError with nil", func(t *testing.T) {
		err := SignError{Err: nil}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "sign error")
	})

	t.Run("VerifyError", func(t *testing.T) {
		err := VerifyError{Err: assert.AnError}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "verify error")
	})

	t.Run("VerifyError with nil", func(t *testing.T) {
		err := VerifyError{Err: nil}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "verify error")
	})

	t.Run("ReadError", func(t *testing.T) {
		err := ReadError{Err: assert.AnError}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "read error")
	})

	t.Run("ReadError with nil", func(t *testing.T) {
		err := ReadError{Err: nil}
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "read error")
	})

	t.Run("NoSignatureError", func(t *testing.T) {
		err := NoSignatureError{}
		expected := "crypto/ed25519: no signature provided for verification"
		assert.Equal(t, expected, err.Error())
	})
}

// TestStreamSignerWriteBufferGrowth tests the buffer growth strategy in Write method
func TestStreamSignerWriteBufferGrowth(t *testing.T) {
	t.Run("write with buffer capacity expansion - newCap < 2*cap", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		// Write initial data to create buffer with specific capacity
		initialData := make([]byte, 100)
		n, err := signer.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)

		// Write data that requires expansion but newCap < 2*cap
		// This should trigger the first branch: newCap = len(s.buffer) + len(p)
		expansionData := make([]byte, 50) // This will make newCap = 150, which is < 2*100
		n, err = signer.Write(expansionData)
		assert.Nil(t, err)
		assert.Equal(t, 50, n)
		assert.Equal(t, 150, len(streamSigner.buffer))
		// Capacity should be expanded to exactly what's needed
		assert.True(t, cap(streamSigner.buffer) >= 150)
	})

	t.Run("write with buffer capacity expansion - newCap >= 2*cap", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		// Write initial data to create buffer with specific capacity
		initialData := make([]byte, 100)
		n, err := signer.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)

		// Write data that requires expansion and newCap >= 2*cap
		// This should trigger the second branch: newCap = len(s.buffer) + len(p)
		largeExpansionData := make([]byte, 150) // This will make newCap = 250, which is >= 2*100
		n, err = signer.Write(largeExpansionData)
		assert.Nil(t, err)
		assert.Equal(t, 150, n)
		assert.Equal(t, 250, len(streamSigner.buffer))
		// When newCap >= 2*cap, capacity should be expanded to len(s.buffer) + len(p)
		assert.Equal(t, 250, cap(streamSigner.buffer))
	})

	t.Run("write with buffer capacity expansion - edge case", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		// Write initial data to create buffer with specific capacity
		initialData := make([]byte, 10)
		n, err := signer.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 10, n)
		initialCap := cap(streamSigner.buffer)

		// Write data that triggers the 2*cap condition exactly
		// This should trigger the second branch: newCap = 2 * cap(s.buffer)
		exactExpansionData := make([]byte, 10) // This will make newCap = 20, which equals 2*10
		n, err = signer.Write(exactExpansionData)
		assert.Nil(t, err)
		assert.Equal(t, 10, n)
		assert.Equal(t, 20, len(streamSigner.buffer))
		// When newCap = 2*cap, capacity should be expanded to 2 * initialCap
		assert.Equal(t, 2*initialCap, cap(streamSigner.buffer))
	})

	t.Run("write with buffer capacity expansion - multiple expansions", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		// Write data in multiple chunks to test different expansion scenarios
		chunk1 := make([]byte, 50)
		n, err := signer.Write(chunk1)
		assert.Nil(t, err)
		assert.Equal(t, 50, n)

		chunk2 := make([]byte, 100) // This will trigger expansion: newCap = 150, which is >= 2*50
		n, err = signer.Write(chunk2)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)
		assert.Equal(t, 150, len(streamSigner.buffer))
		cap2 := cap(streamSigner.buffer)
		// Capacity should be expanded, but exact value depends on Go's slice growth strategy
		assert.True(t, cap2 >= 150)

		chunk3 := make([]byte, 50) // This will fit within existing capacity
		n, err = signer.Write(chunk3)
		assert.Nil(t, err)
		assert.Equal(t, 50, n)
		assert.Equal(t, 200, len(streamSigner.buffer))
		// Capacity should remain the same since no expansion is needed
		// Note: capacity might change due to Go's slice growth strategy
		assert.True(t, cap(streamSigner.buffer) >= cap2)

		chunk4 := make([]byte, 100) // This will trigger expansion again: newCap = 300, which is >= 2*100
		n, err = signer.Write(chunk4)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)
		assert.Equal(t, 300, len(streamSigner.buffer))
		cap3 := cap(streamSigner.buffer)
		assert.Equal(t, 300, cap3) // When newCap >= 2*cap, use len(s.buffer) + len(p)
	})

	t.Run("write with buffer capacity expansion - no expansion needed", func(t *testing.T) {
		var buf bytes.Buffer
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()

		signer := NewStreamSigner(&buf, kp)
		streamSigner, ok := signer.(*StreamSigner)
		assert.True(t, ok)

		// Write initial data to create buffer with sufficient capacity
		initialData := make([]byte, 100)
		n, err := signer.Write(initialData)
		assert.Nil(t, err)
		assert.Equal(t, 100, n)
		initialCap := cap(streamSigner.buffer)

		// Write data that fits within existing capacity
		// This should not trigger the expansion branch
		smallData := make([]byte, 50)
		n, err = signer.Write(smallData)
		assert.Nil(t, err)
		assert.Equal(t, 50, n)
		assert.Equal(t, 150, len(streamSigner.buffer))
		// Capacity should remain the same since no expansion is needed
		// Note: initial capacity might be larger than 100 due to Go's slice growth strategy
		assert.True(t, cap(streamSigner.buffer) >= initialCap)
	})
}

package crypto

import (
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/crypto/sm2"
	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// TestEncrypterBySm2 tests Encrypter.BySm2 method
func TestEncrypterBySm2(t *testing.T) {
	t.Run("standard encryption mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Test string input
		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		// Test bytes input
		enc2 := NewEncrypter().FromBytes([]byte("hello world")).BySm2(kp)
		assert.Nil(t, enc2.Error)
		assert.NotEmpty(t, enc2.dst)

		// Results should differ due to randomness
		assert.NotEqual(t, enc.dst, enc2.dst)

		// But decryption should return same result
		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())

		dec2 := NewDecrypter().FromRawBytes(enc2.dst).BySm2(kp)
		assert.Nil(t, dec2.Error)
		assert.Equal(t, "hello world", dec2.ToString())
	})

	t.Run("streaming encryption mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		file := mock.NewFile([]byte("hello world"), "test.txt")
		defer file.Close()

		enc := NewEncrypter().FromFile(file).BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		// Verify decryption
		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		enc := Encrypter{Error: assert.AnError}
		result := enc.FromString("hello world").BySm2(kp)
		assert.Equal(t, assert.AnError, result.Error)
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("encryption error with invalid public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetPublicKey([]byte("invalid key"))

		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, sm2.EncryptError{}, enc.Error)
	})

	t.Run("streaming encryption error with invalid public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetPublicKey([]byte("invalid key"))

		file := mock.NewFile([]byte("hello world"), "test.txt")
		defer file.Close()

		enc := NewEncrypter().FromFile(file).BySm2(kp)
		assert.NotNil(t, enc.Error)
	})

	t.Run("empty source data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Test empty string
		enc := NewEncrypter().FromString("").BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.Empty(t, enc.dst)

		// Test empty bytes
		enc2 := NewEncrypter().FromBytes([]byte{}).BySm2(kp)
		assert.Nil(t, enc2.Error)
		assert.Empty(t, enc2.dst)

		// Test nil source
		enc3 := NewEncrypter()
		enc3.src = nil
		enc3.BySm2(kp)
		assert.Nil(t, enc3.Error)
		assert.Empty(t, enc3.dst)
	})

	t.Run("streaming encryption with read error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		file := mock.NewErrorReadWriteCloser(assert.AnError)
		enc := NewEncrypter()
		enc.reader = file
		enc.BySm2(kp)
		_ = enc.Error
		_ = enc.dst
	})

	t.Run("C1C2C3 order", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetOrder(keypair.C1C2C3)
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("C1C3C2 order (default)", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetOrder(keypair.C1C3C2)
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

}

// TestDecrypterBySm2 tests Decrypter.BySm2 method
func TestDecrypterBySm2(t *testing.T) {
	t.Run("standard decryption mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Encrypt data first
		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.Nil(t, enc.Error)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("streaming decryption mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Encrypt data first
		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.Nil(t, enc.Error)

		file := mock.NewFile(enc.dst, "test.txt")
		defer file.Close()

		dec := NewDecrypter().FromRawFile(file).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		dec := Decrypter{Error: assert.AnError}
		result := dec.FromRawString("hello world").BySm2(kp)
		assert.Equal(t, assert.AnError, result.Error)
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("decryption error with invalid private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetPrivateKey([]byte("invalid key"))

		dec := NewDecrypter().FromRawString("hello world").BySm2(kp)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, sm2.DecryptError{}, dec.Error)
	})

	t.Run("streaming decryption error with invalid private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetPrivateKey([]byte("invalid key"))

		file := mock.NewFile([]byte("hello world"), "test.txt")
		defer file.Close()

		dec := NewDecrypter().FromRawFile(file).BySm2(kp)
		assert.NotNil(t, dec.Error)
	})

	t.Run("empty source data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Test empty string
		dec := NewDecrypter().FromRawString("").BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Empty(t, dec.dst)

		// Test empty bytes
		dec2 := NewDecrypter().FromRawBytes([]byte{}).BySm2(kp)
		assert.Nil(t, dec2.Error)
		assert.Empty(t, dec2.dst)

		// Test nil source
		dec3 := NewDecrypter()
		dec3.src = nil
		dec3.BySm2(kp)
		assert.Nil(t, dec3.Error)
		assert.Empty(t, dec3.dst)
	})

	t.Run("streaming decryption with read error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		file := mock.NewErrorReadWriteCloser(assert.AnError)
		dec := NewDecrypter()
		dec.reader = file
		dec.BySm2(kp)
		_ = dec.Error
		_ = dec.dst
	})

	t.Run("C1C2C3 order", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetOrder(keypair.C1C2C3)
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Encrypt data first
		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.Nil(t, enc.Error)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("C1C3C2 order (default)", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetOrder(keypair.C1C3C2)
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Encrypt data first
		enc := NewEncrypter().FromString("hello world").BySm2(kp)
		assert.Nil(t, enc.Error)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("decrypt invalid data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Try to decrypt invalid data
		dec := NewDecrypter().FromRawBytes([]byte("invalid encrypted data")).BySm2(kp)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, sm2.DecryptError{}, dec.Error)
	})

	t.Run("large data encryption and decryption", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		enc := NewEncrypter().FromBytes(largeData).BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, largeData, dec.ToBytes())
	})

	t.Run("unicode data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		unicodeData := "Hello 世界 🌍 测试 🧪"

		enc := NewEncrypter().FromString(unicodeData).BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, unicodeData, dec.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}

		enc := NewEncrypter().FromBytes(binaryData).BySm2(kp)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).BySm2(kp)
		assert.Nil(t, dec.Error)
		assert.Equal(t, binaryData, dec.ToBytes())
	})
}

// TestSignerBySm2 tests Signer.BySm2 method
func TestSignerBySm2(t *testing.T) {
	t.Run("standard signing mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Test string input
		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)

		// Test bytes input
		signer2 := NewSigner().FromBytes([]byte("hello world")).BySm2(kp)
		assert.Nil(t, signer2.Error)
		assert.NotEmpty(t, signer2.sign)

		// Signatures should differ due to randomness in k
		assert.NotEqual(t, signer.sign, signer2.sign)

		// But both should verify successfully
		verifier := NewVerifier().FromString("hello world").WithRawSign(signer.sign).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())

		verifier2 := NewVerifier().FromString("hello world").WithRawSign(signer2.sign).BySm2(kp)
		assert.Nil(t, verifier2.Error)
		assert.True(t, verifier2.ToBool())
	})

	t.Run("streaming signing mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		file := mock.NewFile([]byte("hello world"), "test.txt")
		defer file.Close()

		signer := NewSigner().FromFile(file).BySm2(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)

		// Verify the signature
		verifier := NewVerifier().FromString("hello world").WithRawSign(signer.sign).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		signer := Signer{Error: assert.AnError}
		result := signer.FromString("hello world").BySm2(kp)
		assert.Equal(t, assert.AnError, result.Error)
		assert.Nil(t, result.sign)
	})

	t.Run("signing error with empty private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()

		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, sm2.SignError{}, signer.Error)
	})

	t.Run("signing error with invalid private key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetPrivateKey([]byte("invalid key"))

		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.NotNil(t, signer.Error)
		assert.IsType(t, sm2.SignError{}, signer.Error)
	})

	t.Run("empty source data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Test empty string
		signer := NewSigner().FromString("").BySm2(kp)
		assert.Nil(t, signer.Error)
		assert.Empty(t, signer.sign)

		// Test empty bytes
		signer2 := NewSigner().FromBytes([]byte{}).BySm2(kp)
		assert.Nil(t, signer2.Error)
		assert.Empty(t, signer2.sign)
	})

	t.Run("with custom UID", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		customUID := []byte("user@example.com")
		kp.SetUID(customUID)

		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)

		// Verify with same UID
		verifier := NewVerifier().FromString("hello world").WithRawSign(signer.sign).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())
	})

	t.Run("hex encoding", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)

		hexSig := signer.ToHexBytes()
		assert.NotEmpty(t, hexSig)

		verifier := NewVerifier().FromString("hello world").WithHexSign(hexSig).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())
	})

	t.Run("base64 encoding", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)

		b64Sig := signer.ToBase64Bytes()
		assert.NotEmpty(t, b64Sig)

		verifier := NewVerifier().FromString("hello world").WithBase64Sign(b64Sig).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())
	})

	t.Run("unicode data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		unicodeData := "Hello 世界 🌍 测试 🧪"

		signer := NewSigner().FromString(unicodeData).BySm2(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)

		verifier := NewVerifier().FromString(unicodeData).WithRawSign(signer.sign).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())
	})

	t.Run("large data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		signer := NewSigner().FromBytes(largeData).BySm2(kp)
		assert.Nil(t, signer.Error)
		assert.NotEmpty(t, signer.sign)

		verifier := NewVerifier().FromBytes(largeData).WithRawSign(signer.sign).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())
	})
}

// TestVerifierBySm2 tests Verifier.BySm2 method
func TestVerifierBySm2(t *testing.T) {
	t.Run("standard verification mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Sign data first
		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)

		// Test verification
		verifier := NewVerifier().FromString("hello world").WithRawSign(signer.sign).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.ToBool())
	})

	t.Run("streaming verification mode", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Sign data first
		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)

		// Create a file with the signature
		sigFile := mock.NewFile(signer.sign, "signature.bin")
		defer sigFile.Close()

		// Test streaming verification with data
		verifier := NewVerifier().FromString("hello world").FromFile(sigFile).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.True(t, verifier.verify)
	})

	t.Run("streaming verification mode with empty data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Sign empty data
		signer := NewSigner().FromString("").BySm2(kp)
		assert.Nil(t, signer.Error)

		// Create a file with the signature
		sigFile := mock.NewFile(signer.sign, "signature.bin")
		defer sigFile.Close()

		// Test streaming verification with empty data
		verifier := NewVerifier().FromString("").FromFile(sigFile).BySm2(kp)
		assert.Nil(t, verifier.Error)
		// Empty data verification should succeed if signature is valid
		assert.True(t, verifier.verify)
	})

	t.Run("streaming verification error with invalid public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetPublicKey([]byte("invalid key"))

		// Create a file with some signature data
		sigFile := mock.NewFile([]byte("signature"), "signature.bin")
		defer sigFile.Close()

		verifier := NewVerifier().FromString("hello world").FromFile(sigFile).BySm2(kp)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, sm2.VerifyError{}, verifier.Error)
	})

	t.Run("streaming verification error with read error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Create an error file that will fail on read
		errorFile := mock.NewErrorFile(assert.AnError)

		verifier := NewVerifier().FromString("hello world").FromFile(errorFile).BySm2(kp)
		assert.NotNil(t, verifier.Error)
	})

	t.Run("standard verification with empty data and no signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Test with empty data and no signature - should not set verify to true
		verifier := NewVerifier().FromString("").BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.False(t, verifier.verify)
	})

	t.Run("standard verification with valid signature but invalid result", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Sign data
		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)

		// Verify with wrong data - should return error and verify should be false
		verifier := NewVerifier().FromString("wrong data").WithRawSign(signer.sign).BySm2(kp)
		assert.NotNil(t, verifier.Error)
		assert.False(t, verifier.verify)
	})

	t.Run("with existing error", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		verifier := Verifier{Error: assert.AnError}
		result := verifier.FromString("hello world").BySm2(kp)
		assert.Equal(t, assert.AnError, result.Error)
		assert.False(t, result.verify)
	})

	t.Run("verification error with empty public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()

		verifier := NewVerifier().FromString("hello world").WithRawSign([]byte("sig")).BySm2(kp)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, sm2.VerifyError{}, verifier.Error)
	})

	t.Run("verification error with invalid public key", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		kp.SetPublicKey([]byte("invalid key"))

		verifier := NewVerifier().FromString("hello world").WithRawSign([]byte("sig")).BySm2(kp)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, sm2.VerifyError{}, verifier.Error)
	})

	t.Run("empty source data", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		// Test empty string
		verifier := NewVerifier().FromString("").WithRawSign([]byte("sig")).BySm2(kp)
		assert.Nil(t, verifier.Error)
		assert.False(t, verifier.verify)

		// Test empty bytes
		verifier2 := NewVerifier().FromBytes([]byte{}).WithRawSign([]byte("sig")).BySm2(kp)
		assert.Nil(t, verifier2.Error)
		assert.False(t, verifier2.verify)
	})

	t.Run("empty signature", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		verifier := NewVerifier().FromString("hello world").WithRawSign([]byte{}).BySm2(kp)
		assert.NotNil(t, verifier.Error)
	})

	t.Run("invalid signature format", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		invalidSig := []byte{0x00, 0x01, 0x02, 0x03}
		verifier := NewVerifier().FromString("hello world").WithRawSign(invalidSig).BySm2(kp)
		assert.NotNil(t, verifier.Error)
		assert.IsType(t, sm2.VerifyError{}, verifier.Error)
	})

	t.Run("wrong message", func(t *testing.T) {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		assert.Nil(t, err)

		signer := NewSigner().FromString("hello world").BySm2(kp)
		assert.Nil(t, signer.Error)

		// Try to verify with different message
		verifier := NewVerifier().FromString("goodbye world").WithRawSign(signer.sign).BySm2(kp)
		assert.NotNil(t, verifier.Error)
		assert.False(t, verifier.ToBool())
	})

	t.Run("different UID", func(t *testing.T) {
		signKp := keypair.NewSm2KeyPair()
		err := signKp.GenKeyPair()
		assert.Nil(t, err)
		signKp.SetUID([]byte("signer@example.com"))

		signer := NewSigner().FromString("hello world").BySm2(signKp)
		assert.Nil(t, signer.Error)

		// Try to verify with different UID
		verifyKp := signKp
		verifyKp.SetUID([]byte("verifier@example.com"))

		verifier := NewVerifier().FromString("hello world").WithRawSign(signer.sign).BySm2(verifyKp)
		assert.False(t, verifier.ToBool())
	})

	t.Run("wrong key pair", func(t *testing.T) {
		kp1 := keypair.NewSm2KeyPair()
		err := kp1.GenKeyPair()
		assert.Nil(t, err)

		kp2 := keypair.NewSm2KeyPair()
		err = kp2.GenKeyPair()
		assert.Nil(t, err)

		signer := NewSigner().FromString("hello world").BySm2(kp1)
		assert.Nil(t, signer.Error)

		// Try to verify with different key pair
		verifier := NewVerifier().FromString("hello world").WithRawSign(signer.sign).BySm2(kp2)
		assert.NotNil(t, verifier.Error)
		assert.False(t, verifier.ToBool())
	})
}

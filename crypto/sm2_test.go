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
		assert.IsType(t, sm2.KeyPairError{}, enc.Error)
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
		assert.IsType(t, sm2.KeyPairError{}, dec.Error)
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

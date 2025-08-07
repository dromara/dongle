package crypto

import (
	stdcipher "crypto/cipher"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/blowfish"
	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// blowfishMockCipherWithKey is a mock implementation of cipher.CipherInterface for testing
type blowfishMockCipherWithKey struct {
	encryptError error
	decryptError error
}

func (m *blowfishMockCipherWithKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *blowfishMockCipherWithKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

func (m *blowfishMockCipherWithKey) GetKey() []byte {
	return []byte("1234567890123456")
}

type blowfishMockCipherWithEmptyKey struct{}

func (m *blowfishMockCipherWithEmptyKey) GetKey() []byte {
	return []byte{}
}

func (m *blowfishMockCipherWithEmptyKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("encrypted"), nil
}

func (m *blowfishMockCipherWithEmptyKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("decrypted"), nil
}

// blowfishMockCipherWithoutKey is a mock cipher that doesn't implement KeyGetter interface
type blowfishMockCipherWithoutKey struct {
	encryptError error
	decryptError error
}

func (m *blowfishMockCipherWithoutKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *blowfishMockCipherWithoutKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

// TestBlowfishPadding tests Blowfish encryption with various padding modes
func TestBlowfishPadding(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC-16 with PKCS7 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "ECB-16 with PKCS7 padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CBC-16 with No padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "ECB-16 with No padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.No)
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).ByBlowfish(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestBlowfishBlockModes tests Blowfish encryption with different block modes
func TestBlowfishBlockModes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "ECB mode",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).ByBlowfish(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestBlowfishKeySizes tests Blowfish encryption with different key sizes
func TestBlowfishKeySizes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
	}{
		{
			name:      "Blowfish-16",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "Blowfish-24",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "Blowfish-32",
			key:       []byte("12345678901234567890123456789012"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cipher.NewCBCCipher()
			c.SetKey(tt.key)
			c.SetIV(tt.iv)
			c.SetPadding(cipher.PKCS7)

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).ByBlowfish(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestBlowfishInputTypes tests Blowfish encryption with different input types
func TestBlowfishInputTypes(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("string input", func(t *testing.T) {
		enc := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("bytes input", func(t *testing.T) {
		enc := NewEncrypter().FromBytes([]byte("hello world")).ByBlowfish(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("hello world"), dec.ToBytes())
	})

	t.Run("raw bytes input", func(t *testing.T) {
		enc := NewEncrypter().FromBytes([]byte("hello world")).ByBlowfish(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("hello world"), dec.ToBytes())
	})
}

// TestBlowfishErrorHandling tests Blowfish error handling scenarios
func TestBlowfishErrorHandling(t *testing.T) {
	t.Run("cipher without KeyGetter interface", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithoutKey{}
		enc := NewEncrypter().FromString("hello world").ByBlowfish(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, blowfish.KeyUnsetError{}, enc.Error)
	})

	t.Run("cipher with empty key", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithEmptyKey{}
		enc := NewEncrypter().FromString("hello world").ByBlowfish(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, blowfish.KeySizeError(0))
	})

	t.Run("with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter()
		enc.Error = assert.AnError
		result := enc.FromString("hello world").ByBlowfish(c)
		assert.Equal(t, enc, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encryption error", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{encryptError: assert.AnError}
		enc := NewEncrypter().FromString("hello world").ByBlowfish(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, blowfish.EncryptError{}, enc.Error)
	})

	t.Run("decryption error", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{decryptError: assert.AnError}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByBlowfish(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, blowfish.DecryptError{}, dec.Error)
	})

	t.Run("decrypter with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewDecrypter()
		dec.Error = assert.AnError
		result := dec.FromRawBytes([]byte("test")).ByBlowfish(c)
		assert.Equal(t, dec, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decrypter cipher without KeyGetter interface", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithoutKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByBlowfish(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, blowfish.KeyUnsetError{}, dec.Error)
	})

	t.Run("decrypter cipher with empty key", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithEmptyKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByBlowfish(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, blowfish.KeySizeError(0))
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("")) // Invalid key length
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, blowfish.KeySizeError(0))
	})
}

// TestBlowfishEdgeCases tests Blowfish encryption edge cases
func TestBlowfishEdgeCases(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("single character", func(t *testing.T) {
		enc := NewEncrypter().FromString("a").ByBlowfish(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "a", dec.ToString())
	})

	t.Run("exactly one block", func(t *testing.T) {
		data := make([]byte, 8)
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByBlowfish(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("multiple blocks", func(t *testing.T) {
		data := make([]byte, 24) // 3 blocks
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByBlowfish(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("empty input", func(t *testing.T) {
		enc := NewEncrypter().FromString("").ByBlowfish(c)
		assert.Nil(t, enc.Error)
		// Empty input might result in empty output depending on the implementation
		// We only check that there's no error

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Empty(t, dec.ToString())
	})
}

// TestBlowfishIntegration tests Blowfish integration scenarios
func TestBlowfishIntegration(t *testing.T) {
	t.Run("multiple operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Test string input
		enc := NewEncrypter().FromString("hello").ByBlowfish(c)
		assert.Nil(t, enc.Error)
		encrypted1 := enc.dst

		// Test bytes input
		enc = NewEncrypter().FromBytes([]byte("hello")).ByBlowfish(c)
		assert.Nil(t, enc.Error)
		encrypted2 := enc.dst

		// Results should be identical
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(encrypted1).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello", dec.ToString())
	})

	t.Run("chained operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().
			FromString("test").
			ByBlowfish(c)

		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		// Test output methods
		hexStr := enc.ToHexString()
		assert.NotEmpty(t, hexStr)

		base64Str := enc.ToBase64String()
		assert.NotEmpty(t, base64Str)
	})

	t.Run("different input types same result", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		input := "test data"

		// String input
		enc1 := NewEncrypter().FromString(input).ByBlowfish(c)
		assert.Nil(t, enc1.Error)

		// Bytes input
		enc2 := NewEncrypter().FromBytes([]byte(input)).ByBlowfish(c)
		assert.Nil(t, enc2.Error)

		// All should produce the same encrypted result
		assert.Equal(t, enc1.dst, enc2.dst)
	})

	t.Run("encryption with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter()
		enc.Error = assert.AnError
		result := enc.FromString("hello world").ByBlowfish(c)
		assert.Equal(t, enc, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decryption with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewDecrypter()
		dec.Error = assert.AnError
		result := dec.FromRawBytes([]byte("test")).ByBlowfish(c)
		assert.Equal(t, dec, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encryption error from blowfish", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{encryptError: assert.AnError}
		enc := NewEncrypter().FromString("hello world").ByBlowfish(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.Contains(t, enc.Error.Error(), "assert.AnError general error for testing")
	})

	t.Run("decryption error from blowfish", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{decryptError: assert.AnError}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByBlowfish(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.Contains(t, dec.Error.Error(), "assert.AnError general error for testing")
	})
}

// TestBlowfishStreaming tests Blowfish streaming encryption and decryption
func TestBlowfishStreaming(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("stream encrypter with valid key", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := blowfish.NewStreamEncrypter(&buf, c, []byte("1234567890123456"))

		// Write data
		n, err := streamEnc.Write([]byte("hello world"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)

		// Close stream
		err = streamEnc.Close()
		assert.Nil(t, err)

		// Verify encrypted data
		assert.NotEmpty(t, buf.String())
	})

	t.Run("stream encrypter with invalid key", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := blowfish.NewStreamEncrypter(&buf, c, []byte("")) // 0 bytes, invalid

		// Write should fail due to invalid key
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, blowfish.KeySizeError(0))
	})

	t.Run("stream encrypter with empty data", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := blowfish.NewStreamEncrypter(&buf, c, []byte("1234567890123456"))

		// Write empty data
		n, err := streamEnc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)

		err = streamEnc.Close()
		assert.Nil(t, err)
	})

	t.Run("stream encrypter with encryption error", func(t *testing.T) {
		var buf strings.Builder
		mockCipher := &blowfishMockCipherWithKey{encryptError: assert.AnError}
		streamEnc := blowfish.NewStreamEncrypter(&buf, mockCipher, []byte("1234567890123456"))

		// Write should fail due to encryption error
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Contains(t, err.Error(), "assert.AnError general error for testing")
	})

	t.Run("stream encrypter from reader", func(t *testing.T) {
		mockFile := mock.NewFile([]byte("hello world"), "test.txt")
		enc := NewEncrypter().FromFile(mockFile).ByBlowfish(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)
	})
}

// TestBlowfishStdEncrypter tests Blowfish standard encrypter
func TestBlowfishStdEncrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std encrypter with valid key", func(t *testing.T) {
		enc := blowfish.NewStdEncrypter(c, []byte("1234567890123456"))
		assert.Nil(t, enc.Error)
	})

	t.Run("new std encrypter with invalid key", func(t *testing.T) {
		enc := blowfish.NewStdEncrypter(c, []byte("")) // 0 bytes, invalid
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, blowfish.KeySizeError(0))
	})

	t.Run("std encrypter encrypt with existing error", func(t *testing.T) {
		enc := blowfish.NewStdEncrypter(c, []byte("")) // Invalid key
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, blowfish.KeySizeError(0))
	})

	t.Run("std encrypter encrypt empty data", func(t *testing.T) {
		enc := blowfish.NewStdEncrypter(c, []byte("1234567890123456"))
		_, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		// Empty data might result in empty output depending on the implementation
		// We only check that there's no error
	})

	t.Run("std encrypter encrypt with encryption error", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{encryptError: assert.AnError}
		enc := blowfish.NewStdEncrypter(mockCipher, []byte("1234567890123456"))
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Contains(t, err.Error(), "assert.AnError general error for testing")
	})
}

// TestBlowfishStdDecrypter tests Blowfish standard decrypter
func TestBlowfishStdDecrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std decrypter with valid key", func(t *testing.T) {
		dec := blowfish.NewStdDecrypter(c, []byte("1234567890123456"))
		assert.Nil(t, dec.Error)
	})

	t.Run("new std decrypter with invalid key", func(t *testing.T) {
		dec := blowfish.NewStdDecrypter(c, []byte("")) // 0 bytes, invalid
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, blowfish.KeySizeError(0))
	})

	t.Run("std decrypter decrypt with existing error", func(t *testing.T) {
		dec := blowfish.NewStdDecrypter(c, []byte("")) // Invalid key
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, blowfish.KeySizeError(0))
	})

	t.Run("std decrypter decrypt empty data", func(t *testing.T) {
		dec := blowfish.NewStdDecrypter(c, []byte("1234567890123456"))
		dst, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, dst)
	})

	t.Run("std decrypter decrypt with decryption error", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{decryptError: assert.AnError}
		dec := blowfish.NewStdDecrypter(mockCipher, []byte("1234567890123456"))
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Contains(t, err.Error(), "assert.AnError general error for testing")
	})
}

// TestBlowfishDecrypterComprehensive tests comprehensive Blowfish decrypter scenarios
func TestBlowfishDecrypterComprehensive(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("decrypter with blowfish error", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{decryptError: assert.AnError}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByBlowfish(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.Contains(t, dec.Error.Error(), "assert.AnError general error for testing")
	})

	t.Run("decrypter with empty source", func(t *testing.T) {
		dec := NewDecrypter().FromRawBytes([]byte{}).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte{}, dec.ToBytes())
	})

	t.Run("decrypter with invalid encrypted data", func(t *testing.T) {
		dec := NewDecrypter().FromRawBytes([]byte("invalid data")).ByBlowfish(c)
		assert.NotNil(t, dec.Error) // Blowfish should error on invalid data length
	})
}

// TestBlowfishStreamDecrypter tests Blowfish stream decrypter scenarios
func TestBlowfishStreamDecrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("stream decrypter with valid key", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter
		file := mock.NewFile(enc.dst, "test.txt")
		streamDec := blowfish.NewStreamDecrypter(file, c, []byte("1234567890123456"))

		// Read decrypted data
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)

		// Verify decrypted data
		decrypted := string(buf[:n])
		assert.Equal(t, "hello world", decrypted)
	})

	t.Run("stream decrypter with invalid key", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter with invalid key
		file := mock.NewFile(enc.dst, "test.txt")
		streamDec := blowfish.NewStreamDecrypter(file, c, []byte("")) // 0 bytes, invalid

		// Read should fail due to invalid key
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, blowfish.KeySizeError(0))
	})

	t.Run("stream decrypter with empty data", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		streamDec := blowfish.NewStreamDecrypter(file, c, []byte("1234567890123456"))

		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decrypter with read error", func(t *testing.T) {
		// Create a reader that always returns an error
		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		streamDec := blowfish.NewStreamDecrypter(errorReader, c, []byte("1234567890123456"))

		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, blowfish.ReadError{}, err)
	})

	t.Run("stream decrypter with decryption error", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{decryptError: assert.AnError}
		file := mock.NewFile([]byte("some data"), "test.txt")
		streamDec := blowfish.NewStreamDecrypter(file, mockCipher, []byte("1234567890123456"))

		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, blowfish.DecryptError{}, err)
	})

	t.Run("stream decrypter with buffer too small", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByBlowfish(c)
		assert.Nil(t, enc.Error)

		file := mock.NewFile(enc.dst, "test.txt")
		streamDec := blowfish.NewStreamDecrypter(file, c, []byte("1234567890123456"))

		buf := make([]byte, 5) // Buffer smaller than decrypted data
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 5, n)
		assert.IsType(t, blowfish.BufferError{}, err)
	})

}

// TestBlowfishDecrypterEdgeCases tests Blowfish decrypter edge cases
func TestBlowfishDecrypterEdgeCases(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("decrypter with nil source", func(t *testing.T) {
		dec := NewDecrypter().FromRawBytes(nil).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte{}, dec.ToBytes())
	})

	t.Run("decrypter with single byte", func(t *testing.T) {
		// First encrypt a single byte
		enc := NewEncrypter().FromString("a").ByBlowfish(c)
		assert.Nil(t, enc.Error)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "a", dec.ToString())
	})

	t.Run("decrypter with exactly block size", func(t *testing.T) {
		data := make([]byte, 8) // Blowfish block size
		for i := range data {
			data[i] = byte(i)
		}

		enc := NewEncrypter().FromBytes(data).ByBlowfish(c)
		assert.Nil(t, enc.Error)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("decrypter with multiple blocks", func(t *testing.T) {
		data := make([]byte, 24) // 3 blocks
		for i := range data {
			data[i] = byte(i)
		}

		enc := NewEncrypter().FromBytes(data).ByBlowfish(c)
		assert.Nil(t, enc.Error)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})
}

// TestBlowfishDecrypterErrorPaths tests additional error paths in decrypter
func TestBlowfishDecrypterErrorPaths(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("decrypter with existing error", func(t *testing.T) {
		dec := NewDecrypter()
		dec.Error = assert.AnError
		result := dec.ByBlowfish(c)
		assert.Equal(t, dec, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decrypter with blowfish.NewStdDecrypter error", func(t *testing.T) {
		invalidKey := []byte("") // Invalid key length
		mockCipher := &blowfishMockCipherWithKey{}
		dec := blowfish.NewStdDecrypter(mockCipher, invalidKey)
		dst, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, blowfish.KeySizeError(0))
	})

	t.Run("decrypter with blowfish.NewStdDecrypter success but decrypt error", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithKey{decryptError: assert.AnError}
		dec := blowfish.NewStdDecrypter(mockCipher, []byte("1234567890123456"))
		dst, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, blowfish.DecryptError{}, err)
	})

	t.Run("decrypter with blowfish.NewStdDecrypter error in constructor", func(t *testing.T) {
		mockCipher := &blowfishMockCipherWithoutKey{}
		dec := blowfish.NewStdDecrypter(mockCipher, nil)
		dst, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, blowfish.KeySizeError(0))
	})
}

// TestBlowfishDecrypterStreamBranchCustom tests the stream branch with custom decrypter
func TestBlowfishDecrypterStreamBranchCustom(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	// First encrypt some data
	enc := NewEncrypter().FromString("hello world").ByBlowfish(c)
	assert.Nil(t, enc.Error)

	// Create a custom decrypter with reader
	dec := &Decrypter{
		src:    enc.dst,
		reader: mock.NewFile(enc.dst, "test.txt"),
	}

	// Call ByBlowfish which should take the stream branch
	result := dec.ByBlowfish(c)
	assert.Nil(t, result.Error)
	assert.NotEmpty(t, result.dst)
}

// TestBlowfishDecrypterStreamBranchCustomError tests the stream branch with custom decrypter and error
func TestBlowfishDecrypterStreamBranchCustomError(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	// Create a custom decrypter with error reader
	dec := &Decrypter{
		src:    []byte("test"),
		reader: mock.NewErrorReadWriteCloser(assert.AnError),
	}

	// Call ByBlowfish which should take the stream branch and encounter error
	result := dec.ByBlowfish(c)
	assert.NotNil(t, result.Error)
}

// TestBlowfishPackageDirect tests direct functions in blowfish package
func TestBlowfishPackageDirect(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("NewStdEncrypter with invalid key", func(t *testing.T) {
		enc := blowfish.NewStdEncrypter(c, []byte(""))
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, blowfish.KeySizeError(0))
	})

	t.Run("NewStdDecrypter with invalid key", func(t *testing.T) {
		dec := blowfish.NewStdDecrypter(c, []byte(""))
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, blowfish.KeySizeError(0))
	})

	t.Run("NewStreamEncrypter with invalid key", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := blowfish.NewStreamEncrypter(&buf, c, []byte(""))
		assert.NotNil(t, streamEnc.(*blowfish.StreamEncrypter).Error)
		assert.Equal(t, streamEnc.(*blowfish.StreamEncrypter).Error, blowfish.KeySizeError(0))
	})

	t.Run("NewStreamDecrypter with invalid key", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		streamDec := blowfish.NewStreamDecrypter(file, c, []byte(""))
		assert.NotNil(t, streamDec.(*blowfish.StreamDecrypter).Error)
		assert.Equal(t, streamDec.(*blowfish.StreamDecrypter).Error, blowfish.KeySizeError(0))
	})

	t.Run("StreamEncrypter Write with error", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := blowfish.NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		// Set error manually
		streamEnc.(*blowfish.StreamEncrypter).Error = assert.AnError
		n, err := streamEnc.Write([]byte("test"))
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("StreamDecrypter Read with error", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		streamDec := blowfish.NewStreamDecrypter(file, c, []byte("1234567890123456"))
		// Set error manually
		streamDec.(*blowfish.StreamDecrypter).Error = assert.AnError
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("StreamEncrypter Close with closer", func(t *testing.T) {
		var buf strings.Builder
		closer := mock.NewWriteCloser(&buf)
		streamEnc := blowfish.NewStreamEncrypter(closer, c, []byte("1234567890123456"))
		err := streamEnc.Close()
		assert.Nil(t, err)
	})

	t.Run("StreamEncrypter Close without closer", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := blowfish.NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		err := streamEnc.Close()
		assert.Nil(t, err)
	})
}

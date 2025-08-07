package crypto

import (
	stdcipher "crypto/cipher"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/aes"
	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// aesMockCipherWithKey is a mock implementation of cipher.CipherInterface for testing
type aesMockCipherWithKey struct {
	encryptError error
	decryptError error
}

func (m *aesMockCipherWithKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *aesMockCipherWithKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

func (m *aesMockCipherWithKey) GetKey() []byte {
	return []byte("1234567890123456")
}

type aesMockCipherWithEmptyKey struct{}

func (m *aesMockCipherWithEmptyKey) GetKey() []byte {
	return []byte{}
}

func (m *aesMockCipherWithEmptyKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("encrypted"), nil
}

func (m *aesMockCipherWithEmptyKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("decrypted"), nil
}

// aesMockCipherWithoutKey is a mock cipher that doesn't implement KeyGetter interface
type aesMockCipherWithoutKey struct {
	encryptError error
	decryptError error
}

func (m *aesMockCipherWithoutKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *aesMockCipherWithoutKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

// TestAESPadding tests AES encryption with various padding modes
func TestAESPadding(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC-128 with PKCS7 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CBC-128 with No padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("1234567890123456"), // 16 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "CBC-128 with Empty padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "CBC-128 with Zero padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "CBC-128 with ANSI X.923 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "CBC-128 with ISO9797-1 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "CBC-128 with ISO10126 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "CBC-128 with ISO7816-4 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "CBC-128 with Bit padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.Bit)
				return c
			},
		},
		{
			name:      "ECB-128 with PKCS7 padding",
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
			name:      "ECB-128 with No padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("1234567890123456"), // 16 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "ECB-128 with Empty padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "ECB-128 with Zero padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "ECB-128 with ANSI X.923 padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "ECB-128 with ISO9797-1 padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "ECB-128 with ISO10126 padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "ECB-128 with ISO7816-4 padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "ECB-128 with Bit padding",
			key:       []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.Bit)
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).ByAes(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestAESBlockModes tests AES encryption with different block modes
func TestAESBlockModes(t *testing.T) {
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
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CTR mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCTRCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
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
		{
			name:      "CFB mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCFBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				return c
			},
		},
		{
			name:      "OFB mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewOFBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				return c
			},
		},
		{
			name:      "GCM mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewGCMCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetNonce([]byte("123456789012")) // GCM requires 12-byte nonce
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).ByAes(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestAESKeySizes tests AES encryption with different key sizes
func TestAESKeySizes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
	}{
		{
			name:      "AES-128",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "AES-192",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("1234567890123456"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "AES-256",
			key:       []byte("12345678901234567890123456789012"),
			iv:        []byte("1234567890123456"),
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
			enc := NewEncrypter().FromBytes(tt.plaintext).ByAes(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestAESInputTypes tests AES encryption with different input types
func TestAESInputTypes(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	t.Run("string input", func(t *testing.T) {
		enc := NewEncrypter().FromString("hello world").ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("bytes input", func(t *testing.T) {
		enc := NewEncrypter().FromBytes([]byte("hello world")).ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("hello world"), dec.ToBytes())
	})

	t.Run("empty input", func(t *testing.T) {
		enc := NewEncrypter().FromString("").ByAes(c)
		assert.Nil(t, enc.Error)
		assert.Empty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "", dec.ToString())
	})

	t.Run("streaming mode", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		enc := NewEncrypter()
		enc.reader = file
		enc.ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("decrypter streaming mode", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByAes(c)
		assert.Nil(t, enc.Error)

		// Then decrypt using streaming mode
		file := mock.NewFile(enc.dst, "test.txt")
		dec := NewDecrypter()
		dec.reader = file
		dec.ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})
}

// TestAESErrorHandling tests AES error handling scenarios
func TestAESErrorHandling(t *testing.T) {
	t.Run("cipher without KeyGetter interface", func(t *testing.T) {
		mockCipher := &aesMockCipherWithoutKey{}
		enc := NewEncrypter().FromString("hello world").ByAes(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, aes.KeyUnsetError{}, enc.Error)
	})

	t.Run("cipher with empty key", func(t *testing.T) {
		mockCipher := &aesMockCipherWithEmptyKey{}
		enc := NewEncrypter().FromString("hello world").ByAes(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, aes.KeySizeError(0))
	})

	t.Run("with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter()
		enc.Error = assert.AnError
		result := enc.FromString("hello world").ByAes(c)
		assert.Equal(t, enc, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encryption error", func(t *testing.T) {
		mockCipher := &aesMockCipherWithKey{encryptError: assert.AnError}
		enc := NewEncrypter().FromString("hello world").ByAes(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, aes.EncryptError{}, enc.Error)
	})

	t.Run("decryption error", func(t *testing.T) {
		mockCipher := &aesMockCipherWithKey{decryptError: assert.AnError}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByAes(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, aes.DecryptError{}, dec.Error)
	})

	t.Run("decrypter with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		dec := NewDecrypter()
		dec.Error = assert.AnError
		result := dec.FromRawBytes([]byte("test")).ByAes(c)
		assert.Equal(t, dec, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decrypter cipher without KeyGetter interface", func(t *testing.T) {
		mockCipher := &aesMockCipherWithoutKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByAes(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, aes.KeyUnsetError{}, dec.Error)
	})

	t.Run("decrypter cipher with empty key", func(t *testing.T) {
		mockCipher := &aesMockCipherWithEmptyKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByAes(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, aes.KeySizeError(0))
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567")) // Invalid key length
		c.SetIV([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().FromString("hello world").ByAes(c)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, aes.KeySizeError(7))
	})
}

// TestAESEdgeCases tests AES encryption edge cases
func TestAESEdgeCases(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	t.Run("single character", func(t *testing.T) {
		enc := NewEncrypter().FromString("a").ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "a", dec.ToString())
	})

	t.Run("exactly one block", func(t *testing.T) {
		data := make([]byte, 16)
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("multiple blocks", func(t *testing.T) {
		data := make([]byte, 48) // 3 blocks
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("partial block", func(t *testing.T) {
		data := make([]byte, 10) // less than one block
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		enc := NewEncrypter().FromString(data).ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToString())
	})

	t.Run("unicode data", func(t *testing.T) {
		enc := NewEncrypter().FromString("你好世界").ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "你好世界", dec.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		enc := NewEncrypter().FromBytes(binaryData).ByAes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, binaryData, dec.ToBytes())
	})
}

// TestAESIntegration tests AES integration scenarios
func TestAESIntegration(t *testing.T) {
	t.Run("multiple operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		// Test string input
		enc := NewEncrypter().FromString("hello").ByAes(c)
		assert.Nil(t, enc.Error)
		encrypted1 := enc.dst

		// Test bytes input
		enc = NewEncrypter().FromBytes([]byte("hello")).ByAes(c)
		assert.Nil(t, enc.Error)
		encrypted2 := enc.dst

		// Results should be identical
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(encrypted1).ByAes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello", dec.ToString())
	})

	t.Run("chained operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().
			FromString("test").
			ByAes(c)

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
		c.SetIV([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		input := "test data"

		// String input
		enc1 := NewEncrypter().FromString(input).ByAes(c)
		assert.Nil(t, enc1.Error)

		// Bytes input
		enc2 := NewEncrypter().FromBytes([]byte(input)).ByAes(c)
		assert.Nil(t, enc2.Error)

		// All should produce the same encrypted result
		assert.Equal(t, enc1.dst, enc2.dst)
	})
}

// TestAESStreaming tests AES streaming encryption and decryption
func TestAESStreaming(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	t.Run("stream encrypter with valid key", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := aes.NewStreamEncrypter(&buf, c, []byte("1234567890123456"))

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
		streamEnc := aes.NewStreamEncrypter(&buf, c, []byte("1234567")) // 7 bytes, invalid

		// Write should fail due to invalid key
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, aes.KeySizeError(7))
	})

	t.Run("stream encrypter with empty data", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := aes.NewStreamEncrypter(&buf, c, []byte("1234567890123456"))

		// Write empty data
		n, err := streamEnc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)

		err = streamEnc.Close()
		assert.Nil(t, err)
	})

	t.Run("stream encrypter with encryption error", func(t *testing.T) {
		var buf strings.Builder
		mockCipher := &aesMockCipherWithKey{encryptError: assert.AnError}
		streamEnc := aes.NewStreamEncrypter(&buf, mockCipher, []byte("1234567890123456"))

		// Write should fail due to encryption error
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, aes.EncryptError{}, err)
	})

	t.Run("stream decrypter with valid key", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByAes(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter
		file := mock.NewFile(enc.dst, "test.txt")
		streamDec := aes.NewStreamDecrypter(file, c, []byte("1234567890123456"))

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
		file := mock.NewFile([]byte("test data"), "test.txt")
		streamDec := aes.NewStreamDecrypter(file, c, []byte("1234567")) // 7 bytes, invalid

		// Read should fail due to invalid key
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, aes.KeySizeError(7))
	})

	t.Run("stream decrypter with empty data", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		streamDec := aes.NewStreamDecrypter(file, c, []byte("1234567890123456"))

		// Read empty data
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decrypter with read error", func(t *testing.T) {
		// Create a reader that will fail
		reader := mock.NewErrorReadWriteCloser(assert.AnError)
		streamDec := aes.NewStreamDecrypter(reader, c, []byte("1234567890123456"))

		// Read should fail due to read error
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, aes.ReadError{}, err)
	})

	t.Run("stream decrypter with decryption error", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid encrypted data"), "test.txt")
		mockCipher := &aesMockCipherWithKey{decryptError: assert.AnError}
		streamDec := aes.NewStreamDecrypter(file, mockCipher, []byte("1234567890123456"))

		// Read should fail due to decryption error
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, aes.DecryptError{}, err)
	})

	t.Run("stream decrypter with buffer too small", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByAes(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter
		file := mock.NewFile(enc.dst, "test.txt")
		streamDec := aes.NewStreamDecrypter(file, c, []byte("1234567890123456"))

		// Read with buffer too small
		buf := make([]byte, 5) // Too small for "hello world"
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.IsType(t, aes.BufferError{}, err)
		assert.Equal(t, 5, n) // Should copy what it can
	})
}

// TestAESStdEncrypter tests AES standard encrypter
func TestAESStdEncrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std encrypter with valid key", func(t *testing.T) {
		enc := aes.NewStdEncrypter(c, []byte("1234567890123456"))
		assert.Nil(t, enc.Error)
	})

	t.Run("new std encrypter with invalid key", func(t *testing.T) {
		enc := aes.NewStdEncrypter(c, []byte("1234567")) // 7 bytes, invalid
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, aes.KeySizeError(7))
	})

	t.Run("std encrypter encrypt with existing error", func(t *testing.T) {
		enc := aes.NewStdEncrypter(c, []byte("1234567")) // Invalid key
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, aes.KeySizeError(7))
	})

	t.Run("std encrypter encrypt empty data", func(t *testing.T) {
		enc := aes.NewStdEncrypter(c, []byte("1234567890123456"))
		dst, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Empty(t, dst) // Empty data should produce empty output
	})

	t.Run("std encrypter encrypt with encryption error", func(t *testing.T) {
		mockCipher := &aesMockCipherWithKey{encryptError: assert.AnError}
		enc := aes.NewStdEncrypter(mockCipher, []byte("1234567890123456"))
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, aes.EncryptError{}, err)
	})
}

// TestAESStdDecrypter tests AES standard decrypter
func TestAESStdDecrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std decrypter with valid key", func(t *testing.T) {
		dec := aes.NewStdDecrypter(c, []byte("1234567890123456"))
		assert.Nil(t, dec.Error)
	})

	t.Run("new std decrypter with invalid key", func(t *testing.T) {
		dec := aes.NewStdDecrypter(c, []byte("1234567")) // 7 bytes, invalid
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, aes.KeySizeError(7))
	})

	t.Run("std decrypter decrypt with existing error", func(t *testing.T) {
		dec := aes.NewStdDecrypter(c, []byte("1234567")) // Invalid key
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, aes.KeySizeError(7))
	})

	t.Run("std decrypter decrypt empty data", func(t *testing.T) {
		dec := aes.NewStdDecrypter(c, []byte("1234567890123456"))
		dst, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, dst)
	})

	t.Run("std decrypter decrypt with decryption error", func(t *testing.T) {
		mockCipher := &aesMockCipherWithKey{decryptError: assert.AnError}
		dec := aes.NewStdDecrypter(mockCipher, []byte("1234567890123456"))
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, aes.DecryptError{}, err)
	})
}

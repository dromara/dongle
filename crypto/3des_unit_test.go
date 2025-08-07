package crypto

import (
	stdcipher "crypto/cipher"
	"io"
	"strings"
	"testing"

	tripledes "github.com/dromara/dongle/crypto/3des"
	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// threeDesMockCipherWithKey is a mock implementation of cipher.CipherInterface for testing
type threeDesMockCipherWithKey struct {
	encryptError error
	decryptError error
}

func (m *threeDesMockCipherWithKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *threeDesMockCipherWithKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

func (m *threeDesMockCipherWithKey) GetKey() []byte {
	return []byte("123456789012345678901234")
}

type threeDesMockCipherWithEmptyKey struct{}

func (m *threeDesMockCipherWithEmptyKey) GetKey() []byte {
	return []byte{}
}

func (m *threeDesMockCipherWithEmptyKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("encrypted"), nil
}

func (m *threeDesMockCipherWithEmptyKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("decrypted"), nil
}

// threeDesMockCipherWithoutKey is a mock cipher that doesn't implement KeyGetter interface
type threeDesMockCipherWithoutKey struct {
	encryptError error
	decryptError error
}

func (m *threeDesMockCipherWithoutKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *threeDesMockCipherWithoutKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

// Test3DESPadding tests 3DES encryption with various padding modes
func Test3DESPadding(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC-192 with PKCS7 padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CBC-192 with No padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "CBC-192 with Empty padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "CBC-192 with Zero padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "CBC-192 with ANSI X.923 padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "CBC-192 with ISO9797-1 padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "CBC-192 with ISO10126 padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "CBC-192 with ISO7816-4 padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "CBC-192 with Bit padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Bit)
				return c
			},
		},
		{
			name:      "ECB-192 with PKCS7 padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "ECB-192 with No padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "ECB-192 with Empty padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "ECB-192 with Zero padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "ECB-192 with ANSI X.923 padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "ECB-192 with ISO9797-1 padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "ECB-192 with ISO10126 padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "ECB-192 with ISO7816-4 padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "ECB-192 with Bit padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.Bit)
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).By3Des(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// Test3DESBlockModes tests 3DES encryption with different block modes
func Test3DESBlockModes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC mode",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CTR mode",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCTRCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				return c
			},
		},
		{
			name:      "ECB mode",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CFB mode",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCFBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				return c
			},
		},
		{
			name:      "OFB mode",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewOFBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("12345678"))
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).By3Des(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// Test3DESKeySizes tests 3DES encryption with different key sizes
func Test3DESKeySizes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
	}{
		{
			name:      "3DES-128 (16 bytes)",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
		},
		{
			name:      "3DES-192 (24 bytes)",
			key:       []byte("123456789012345678901234"),
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
			enc := NewEncrypter().FromBytes(tt.plaintext).By3Des(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// Test3DESInputTypes tests 3DES encryption with different input types
func Test3DESInputTypes(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("123456789012345678901234"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("string input", func(t *testing.T) {
		enc := NewEncrypter().FromString("hello world").By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("bytes input", func(t *testing.T) {
		enc := NewEncrypter().FromBytes([]byte("hello world")).By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("hello world"), dec.ToBytes())
	})

	t.Run("empty input", func(t *testing.T) {
		enc := NewEncrypter().FromString("").By3Des(c)
		assert.Nil(t, enc.Error)
		// For 3DES, empty input with padding should produce encrypted output
		if len(enc.dst) > 0 {
			dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, "", dec.ToString())
		}
	})

	t.Run("streaming mode", func(t *testing.T) {
		reader := strings.NewReader("hello world")
		enc := NewEncrypter()
		enc.reader = reader
		enc.By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("decrypter streaming mode", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").By3Des(c)
		assert.Nil(t, enc.Error)

		// Then decrypt using streaming mode
		reader := strings.NewReader(string(enc.dst))
		dec := NewDecrypter()
		dec.reader = reader
		dec.By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})
}

// Test3DESErrorHandling tests 3DES error handling scenarios
func Test3DESErrorHandling(t *testing.T) {
	t.Run("cipher without KeyGetter interface", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithoutKey{}
		enc := NewEncrypter().FromString("hello world").By3Des(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, tripledes.KeyUnsetError{}, enc.Error)
	})

	t.Run("cipher with empty key", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithEmptyKey{}
		enc := NewEncrypter().FromString("hello world").By3Des(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, tripledes.KeySizeError(0))
	})

	t.Run("with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter()
		enc.Error = assert.AnError
		result := enc.FromString("hello world").By3Des(c)
		assert.Equal(t, enc, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encryption error", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithKey{encryptError: assert.AnError}
		enc := NewEncrypter().FromString("hello world").By3Des(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, tripledes.EncryptError{}, enc.Error)
	})

	t.Run("decryption error", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithKey{decryptError: assert.AnError}
		dec := NewDecrypter().FromRawBytes([]byte("test")).By3Des(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, tripledes.DecryptError{}, dec.Error)
	})

	t.Run("decrypter with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewDecrypter()
		dec.Error = assert.AnError
		result := dec.FromRawBytes([]byte("test")).By3Des(c)
		assert.Equal(t, dec, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decrypter cipher without KeyGetter interface", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithoutKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).By3Des(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, tripledes.KeyUnsetError{}, dec.Error)
	})

	t.Run("decrypter cipher with empty key", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithEmptyKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).By3Des(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, tripledes.KeySizeError(0))
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567")) // Invalid key length
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().FromString("hello world").By3Des(c)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, tripledes.KeySizeError(7))
	})
}

// Test3DESEdgeCases tests 3DES encryption edge cases
func Test3DESEdgeCases(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("123456789012345678901234"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("single character", func(t *testing.T) {
		enc := NewEncrypter().FromString("a").By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "a", dec.ToString())
	})

	t.Run("exactly one block", func(t *testing.T) {
		data := make([]byte, 8)
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("multiple blocks", func(t *testing.T) {
		data := make([]byte, 24) // 3 blocks
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("partial block", func(t *testing.T) {
		data := make([]byte, 5) // less than one block
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		enc := NewEncrypter().FromString(data).By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToString())
	})

	t.Run("unicode data", func(t *testing.T) {
		enc := NewEncrypter().FromString("你好世界").By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "你好世界", dec.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
		enc := NewEncrypter().FromBytes(binaryData).By3Des(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, binaryData, dec.ToBytes())
	})
}

// Test3DESIntegration tests 3DES integration scenarios
func Test3DESIntegration(t *testing.T) {
	t.Run("multiple operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Test string input
		enc := NewEncrypter().FromString("hello").By3Des(c)
		assert.Nil(t, enc.Error)
		encrypted1 := enc.dst

		// Test bytes input
		enc = NewEncrypter().FromBytes([]byte("hello")).By3Des(c)
		assert.Nil(t, enc.Error)
		encrypted2 := enc.dst

		// Results should be identical
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(encrypted1).By3Des(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello", dec.ToString())
	})

	t.Run("chained operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().
			FromString("test").
			By3Des(c)

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
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		input := "test data"

		// String input
		enc1 := NewEncrypter().FromString(input).By3Des(c)
		assert.Nil(t, enc1.Error)

		// Bytes input
		enc2 := NewEncrypter().FromBytes([]byte(input)).By3Des(c)
		assert.Nil(t, enc2.Error)

		// All should produce the same encrypted result
		assert.Equal(t, enc1.dst, enc2.dst)
	})
}

// Test3DESStreaming tests 3DES streaming encryption and decryption
func Test3DESStreaming(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("123456789012345678901234"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("stream encrypter with valid key", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := tripledes.NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))

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
		streamEnc := tripledes.NewStreamEncrypter(&buf, c, []byte("1234567")) // 7 bytes, invalid

		// Write should fail due to invalid key
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, tripledes.KeySizeError(7))
	})

	t.Run("stream encrypter with empty data", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := tripledes.NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))

		// Write empty data
		n, err := streamEnc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)

		err = streamEnc.Close()
		assert.Nil(t, err)
	})

	t.Run("stream encrypter with encryption error", func(t *testing.T) {
		var buf strings.Builder
		mockCipher := &threeDesMockCipherWithKey{encryptError: assert.AnError}
		streamEnc := tripledes.NewStreamEncrypter(&buf, mockCipher, []byte("123456789012345678901234"))

		// Write should fail due to encryption error
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, tripledes.EncryptError{}, err)
	})

	t.Run("stream decrypter with valid key", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").By3Des(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter
		reader := strings.NewReader(string(enc.dst))
		streamDec := tripledes.NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))

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
		reader := strings.NewReader("test data")
		streamDec := tripledes.NewStreamDecrypter(reader, c, []byte("1234567")) // 7 bytes, invalid

		// Read should fail due to invalid key
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, tripledes.KeySizeError(7))
	})

	t.Run("stream decrypter with empty data", func(t *testing.T) {
		reader := strings.NewReader("")
		streamDec := tripledes.NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))

		// Read empty data
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decrypter with read error", func(t *testing.T) {
		// Create a reader that will fail
		reader := mock.NewErrorReadWriteCloser(assert.AnError)
		streamDec := tripledes.NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))

		// Read should fail due to read error
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, tripledes.ReadError{}, err)
	})

	t.Run("stream decrypter with decryption error", func(t *testing.T) {
		reader := strings.NewReader("invalid encrypted data")
		mockCipher := &threeDesMockCipherWithKey{decryptError: assert.AnError}
		streamDec := tripledes.NewStreamDecrypter(reader, mockCipher, []byte("123456789012345678901234"))

		// Read should fail due to decryption error
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, tripledes.DecryptError{}, err)
	})

	t.Run("stream decrypter with buffer too small", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").By3Des(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter
		reader := strings.NewReader(string(enc.dst))
		streamDec := tripledes.NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))

		// Read with buffer too small
		buf := make([]byte, 5) // Too small for "hello world"
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.IsType(t, tripledes.BufferError{}, err)
		assert.Equal(t, 5, n) // Should copy what it can
	})
}

// Test3DESStdEncrypter tests 3DES standard encrypter
func Test3DESStdEncrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("123456789012345678901234"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std encrypter with valid key", func(t *testing.T) {
		enc := tripledes.NewStdEncrypter(c, []byte("123456789012345678901234"))
		assert.Nil(t, enc.Error)
	})

	t.Run("new std encrypter with invalid key", func(t *testing.T) {
		enc := tripledes.NewStdEncrypter(c, []byte("1234567")) // 7 bytes, invalid
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, tripledes.KeySizeError(7))
	})

	t.Run("std encrypter encrypt with existing error", func(t *testing.T) {
		enc := tripledes.NewStdEncrypter(c, []byte("1234567")) // Invalid key
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, tripledes.KeySizeError(7))
	})

	t.Run("std encrypter encrypt empty data", func(t *testing.T) {
		enc := tripledes.NewStdEncrypter(c, []byte("123456789012345678901234"))
		dst, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, dst)
	})

	t.Run("std encrypter encrypt with encryption error", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithKey{encryptError: assert.AnError}
		enc := tripledes.NewStdEncrypter(mockCipher, []byte("123456789012345678901234"))
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, tripledes.EncryptError{}, err)
	})
}

// Test3DESStdDecrypter tests 3DES standard decrypter
func Test3DESStdDecrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("123456789012345678901234"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std decrypter with valid key", func(t *testing.T) {
		dec := tripledes.NewStdDecrypter(c, []byte("123456789012345678901234"))
		assert.Nil(t, dec.Error)
	})

	t.Run("new std decrypter with invalid key", func(t *testing.T) {
		dec := tripledes.NewStdDecrypter(c, []byte("1234567")) // 7 bytes, invalid
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, tripledes.KeySizeError(7))
	})

	t.Run("std decrypter decrypt with existing error", func(t *testing.T) {
		dec := tripledes.NewStdDecrypter(c, []byte("1234567")) // Invalid key
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, tripledes.KeySizeError(7))
	})

	t.Run("std decrypter decrypt empty data", func(t *testing.T) {
		dec := tripledes.NewStdDecrypter(c, []byte("123456789012345678901234"))
		dst, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, dst)
	})

	t.Run("std decrypter decrypt with decryption error", func(t *testing.T) {
		mockCipher := &threeDesMockCipherWithKey{decryptError: assert.AnError}
		dec := tripledes.NewStdDecrypter(mockCipher, []byte("123456789012345678901234"))
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, tripledes.DecryptError{}, err)
	})
}

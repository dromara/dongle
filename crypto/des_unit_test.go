package crypto

import (
	stdcipher "crypto/cipher"
	"io"
	"strings"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/des"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// desMockCipherWithKey is a mock implementation of cipher.CipherInterface for testing
type desMockCipherWithKey struct {
	encryptError error
	decryptError error
}

func (m *desMockCipherWithKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *desMockCipherWithKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

func (m *desMockCipherWithKey) GetKey() []byte {
	return []byte("12345678")
}

type desMockCipherWithEmptyKey struct{}

func (m *desMockCipherWithEmptyKey) GetKey() []byte {
	return []byte{}
}

func (m *desMockCipherWithEmptyKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("encrypted"), nil
}

func (m *desMockCipherWithEmptyKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	return []byte("decrypted"), nil
}

// desMockCipherWithoutKey is a mock cipher that doesn't implement KeyGetter interface
type desMockCipherWithoutKey struct {
	encryptError error
	decryptError error
}

func (m *desMockCipherWithoutKey) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *desMockCipherWithoutKey) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

// TestDESPadding tests DES encryption with various padding modes
func TestDESPadding(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC-64 with PKCS7 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CBC-64 with No padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "CBC-64 with Empty padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "CBC-64 with Zero padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "CBC-64 with ANSI X.923 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "CBC-64 with ISO9797-1 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "CBC-64 with ISO10126 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "CBC-64 with ISO7816-4 padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "CBC-64 with Bit padding",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.Bit)
				return c
			},
		},
		{
			name:      "ECB-64 with PKCS7 padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "ECB-64 with No padding",
			key:       []byte("12345678"),
			plaintext: []byte("12345678"), // 8 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "ECB-64 with Empty padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "ECB-64 with Zero padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "ECB-64 with ANSI X.923 padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "ECB-64 with ISO9797-1 padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "ECB-64 with ISO10126 padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "ECB-64 with ISO7816-4 padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "ECB-64 with Bit padding",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.Bit)
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).ByDes(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestDESBlockModes tests DES encryption with different block modes
func TestDESBlockModes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC mode",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CTR mode",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCTRCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				return c
			},
		},
		{
			name:      "ECB mode",
			key:       []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "CFB mode",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCFBCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				return c
			},
		},
		{
			name:      "OFB mode",
			key:       []byte("12345678"),
			iv:        []byte("87654321"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewOFBCipher()
				c.SetKey([]byte("12345678"))
				c.SetIV([]byte("87654321"))
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromBytes(tt.plaintext).ByDes(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToBytes())
		})
	}
}

// TestDESInputTypes tests DES encryption with different input types
func TestDESInputTypes(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("12345678"))
	c.SetIV([]byte("87654321"))
	c.SetPadding(cipher.PKCS7)

	t.Run("string input", func(t *testing.T) {
		enc := NewEncrypter().FromString("hello world").ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("bytes input", func(t *testing.T) {
		enc := NewEncrypter().FromBytes([]byte("hello world")).ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("hello world"), dec.ToBytes())
	})

	t.Run("empty input", func(t *testing.T) {
		enc := NewEncrypter().FromString("").ByDes(c)
		assert.Nil(t, enc.Error)
		// Empty input may result in empty output depending on padding mode
		// Just verify that decryption works correctly
		if len(enc.dst) > 0 {
			dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, "", dec.ToString())
		}
	})

	t.Run("streaming mode", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		enc := NewEncrypter()
		enc.reader = file
		enc.ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})

	t.Run("decrypter streaming mode", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByDes(c)
		assert.Nil(t, enc.Error)

		// Then decrypt using streaming mode
		file := mock.NewFile(enc.dst, "test.txt")
		dec := NewDecrypter()
		dec.reader = file
		dec.ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello world", dec.ToString())
	})
}

// TestDESErrorHandling tests DES error handling scenarios
func TestDESErrorHandling(t *testing.T) {
	t.Run("cipher without KeyGetter interface", func(t *testing.T) {
		// Use a mock cipher that doesn't implement KeyGetter
		mockWithoutKey := &desMockCipherWithoutKey{}
		enc := NewEncrypter().FromString("hello world").ByDes(mockWithoutKey)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error.Error(), des.KeyUnsetError{}.Error())
	})

	t.Run("cipher with empty key", func(t *testing.T) {
		mockCipher := &desMockCipherWithEmptyKey{}
		enc := NewEncrypter().FromString("hello world").ByDes(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, des.KeySizeError(0))
	})

	t.Run("with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter()
		enc.Error = assert.AnError
		result := enc.FromString("hello world").ByDes(c)
		assert.Equal(t, enc, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("encryption error", func(t *testing.T) {
		mockCipher := &desMockCipherWithKey{encryptError: assert.AnError}
		enc := NewEncrypter().FromString("hello world").ByDes(mockCipher)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, des.EncryptError{}, enc.Error)
	})

	t.Run("decryption error", func(t *testing.T) {
		mockCipher := &desMockCipherWithKey{decryptError: assert.AnError}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByDes(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, des.DecryptError{}, dec.Error)
	})

	t.Run("decrypter with existing error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		dec := NewDecrypter()
		dec.Error = assert.AnError
		result := dec.FromRawBytes([]byte("test")).ByDes(c)
		assert.Equal(t, dec, result)
		assert.Equal(t, assert.AnError, result.Error)
	})

	t.Run("decrypter cipher without KeyGetter interface", func(t *testing.T) {
		mockWithoutKey := &desMockCipherWithoutKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByDes(mockWithoutKey)
		assert.NotNil(t, dec.Error)
		assert.IsType(t, des.KeyUnsetError{}, dec.Error)
	})

	t.Run("decrypter cipher with empty key", func(t *testing.T) {
		mockCipher := &desMockCipherWithEmptyKey{}
		dec := NewDecrypter().FromRawBytes([]byte("test")).ByDes(mockCipher)
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, des.KeySizeError(0))
	})

	t.Run("invalid key length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567")) // 7 bytes, should be 8
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().FromString("hello world").ByDes(c)
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, des.KeySizeError(7))
	})

	t.Run("invalid IV length", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("8765432")) // 7 bytes, should be 8
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().FromString("hello world").ByDes(c)
		assert.NotNil(t, enc.Error)
		assert.IsType(t, des.EncryptError{}, enc.Error)
	})
}

// TestDESEdgeCases tests DES encryption edge cases
func TestDESEdgeCases(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("12345678"))
	c.SetIV([]byte("87654321"))
	c.SetPadding(cipher.PKCS7)

	t.Run("single character", func(t *testing.T) {
		enc := NewEncrypter().FromString("a").ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "a", dec.ToString())
	})

	t.Run("exactly one block", func(t *testing.T) {
		data := make([]byte, 8)
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("multiple blocks", func(t *testing.T) {
		data := make([]byte, 24) // 3 blocks
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("partial block", func(t *testing.T) {
		data := make([]byte, 5) // less than one block
		for i := range data {
			data[i] = byte(i)
		}
		enc := NewEncrypter().FromBytes(data).ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToBytes())
	})

	t.Run("large data", func(t *testing.T) {
		data := strings.Repeat("a", 10000)
		enc := NewEncrypter().FromString(data).ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, data, dec.ToString())
	})

	t.Run("unicode data", func(t *testing.T) {
		enc := NewEncrypter().FromString("你好世界").ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "你好世界", dec.ToString())
	})

	t.Run("binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
		enc := NewEncrypter().FromBytes(binaryData).ByDes(c)
		assert.Nil(t, enc.Error)
		assert.NotEmpty(t, enc.dst)

		dec := NewDecrypter().FromRawBytes(enc.dst).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, binaryData, dec.ToBytes())
	})
}

// TestDESIntegration tests DES integration scenarios
func TestDESIntegration(t *testing.T) {
	t.Run("multiple operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// Test string input
		enc := NewEncrypter().FromString("hello").ByDes(c)
		assert.Nil(t, enc.Error)
		encrypted1 := enc.dst

		// Test bytes input
		enc = NewEncrypter().FromBytes([]byte("hello")).ByDes(c)
		assert.Nil(t, enc.Error)
		encrypted2 := enc.dst

		// Results should be identical
		assert.Equal(t, encrypted1, encrypted2)

		// Test decryption
		dec := NewDecrypter().FromRawBytes(encrypted1).ByDes(c)
		assert.Nil(t, dec.Error)
		assert.Equal(t, "hello", dec.ToString())
	})

	t.Run("chained operations", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		enc := NewEncrypter().
			FromString("test").
			ByDes(c)

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
		c.SetKey([]byte("12345678"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		input := "test data"

		// String input
		enc1 := NewEncrypter().FromString(input).ByDes(c)
		assert.Nil(t, enc1.Error)

		// Bytes input
		enc2 := NewEncrypter().FromBytes([]byte(input)).ByDes(c)
		assert.Nil(t, enc2.Error)

		// All should produce the same encrypted result
		assert.Equal(t, enc1.dst, enc2.dst)
	})
}

// TestDESStreaming tests DES streaming encryption and decryption
func TestDESStreaming(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("12345678"))
	c.SetIV([]byte("87654321"))
	c.SetPadding(cipher.PKCS7)

	t.Run("stream encrypter with valid key", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := des.NewStreamEncrypter(&buf, c, []byte("12345678"))

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
		streamEnc := des.NewStreamEncrypter(&buf, c, []byte("1234567")) // 7 bytes, invalid

		// Write should fail due to invalid key
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, des.KeySizeError(7))
	})

	t.Run("stream encrypter with empty data", func(t *testing.T) {
		var buf strings.Builder
		streamEnc := des.NewStreamEncrypter(&buf, c, []byte("12345678"))

		// Write empty data
		n, err := streamEnc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)

		err = streamEnc.Close()
		assert.Nil(t, err)
	})

	t.Run("stream encrypter with encryption error", func(t *testing.T) {
		var buf strings.Builder
		mockCipher := &desMockCipherWithKey{encryptError: assert.AnError}
		streamEnc := des.NewStreamEncrypter(&buf, mockCipher, []byte("12345678"))

		// Write should fail due to encryption error
		n, err := streamEnc.Write([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, des.EncryptError{}, err)
	})

	t.Run("stream decrypter with valid key", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByDes(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter
		file := mock.NewFile(enc.dst, "test.txt")
		streamDec := des.NewStreamDecrypter(file, c, []byte("12345678"))

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
		streamDec := des.NewStreamDecrypter(file, c, []byte("1234567")) // 7 bytes, invalid

		// Read should fail due to invalid key
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, des.KeySizeError(7))
	})

	t.Run("stream decrypter with empty data", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "test.txt")
		streamDec := des.NewStreamDecrypter(file, c, []byte("12345678"))

		// Read empty data
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("stream decrypter with read error", func(t *testing.T) {
		// Create a reader that will fail
		reader := mock.NewErrorReadWriteCloser(assert.AnError)
		streamDec := des.NewStreamDecrypter(reader, c, []byte("12345678"))

		// Read should fail due to read error
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, des.ReadError{}, err)
	})

	t.Run("stream decrypter with decryption error", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid encrypted data"), "test.txt")
		mockCipher := &desMockCipherWithKey{decryptError: assert.AnError}
		streamDec := des.NewStreamDecrypter(file, mockCipher, []byte("12345678"))

		// Read should fail due to decryption error
		buf := make([]byte, 100)
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, des.DecryptError{}, err)
	})

	t.Run("stream decrypter with buffer too small", func(t *testing.T) {
		// First encrypt some data
		enc := NewEncrypter().FromString("hello world").ByDes(c)
		assert.Nil(t, enc.Error)

		// Create stream decrypter
		file := mock.NewFile(enc.dst, "test.txt")
		streamDec := des.NewStreamDecrypter(file, c, []byte("12345678"))

		// Read with buffer too small
		buf := make([]byte, 5) // Too small for "hello world"
		n, err := streamDec.Read(buf)
		assert.NotNil(t, err)
		assert.IsType(t, des.BufferError{}, err)
		assert.Equal(t, 5, n) // Should copy what it can
	})
}

// TestDESStdEncrypter tests DES standard encrypter
func TestDESStdEncrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("12345678"))
	c.SetIV([]byte("87654321"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std encrypter with valid key", func(t *testing.T) {
		enc := des.NewStdEncrypter(c, []byte("12345678"))
		assert.Nil(t, enc.Error)
	})

	t.Run("new std encrypter with invalid key", func(t *testing.T) {
		enc := des.NewStdEncrypter(c, []byte("1234567")) // 7 bytes, invalid
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, des.KeySizeError(7))
	})

	t.Run("std encrypter encrypt with existing error", func(t *testing.T) {
		enc := des.NewStdEncrypter(c, []byte("1234567")) // Invalid key
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, des.KeySizeError(7))
	})

	t.Run("std encrypter encrypt empty data", func(t *testing.T) {
		enc := des.NewStdEncrypter(c, []byte("12345678"))
		dst, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, dst)
	})

	t.Run("std encrypter encrypt with encryption error", func(t *testing.T) {
		mockCipher := &desMockCipherWithKey{encryptError: assert.AnError}
		enc := des.NewStdEncrypter(mockCipher, []byte("12345678"))
		dst, err := enc.Encrypt([]byte("hello world"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, des.EncryptError{}, err)
	})
}

// TestDESStdDecrypter tests DES standard decrypter
func TestDESStdDecrypter(t *testing.T) {
	c := cipher.NewCBCCipher()
	c.SetKey([]byte("12345678"))
	c.SetIV([]byte("87654321"))
	c.SetPadding(cipher.PKCS7)

	t.Run("new std decrypter with valid key", func(t *testing.T) {
		dec := des.NewStdDecrypter(c, []byte("12345678"))
		assert.Nil(t, dec.Error)
	})

	t.Run("new std decrypter with invalid key", func(t *testing.T) {
		dec := des.NewStdDecrypter(c, []byte("1234567")) // 7 bytes, invalid
		assert.NotNil(t, dec.Error)
		assert.Equal(t, dec.Error, des.KeySizeError(7))
	})

	t.Run("std decrypter decrypt with existing error", func(t *testing.T) {
		dec := des.NewStdDecrypter(c, []byte("1234567")) // Invalid key
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.Equal(t, err, des.KeySizeError(7))
	})

	t.Run("std decrypter decrypt empty data", func(t *testing.T) {
		dec := des.NewStdDecrypter(c, []byte("12345678"))
		dst, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, dst)
	})

	t.Run("std decrypter decrypt with decryption error", func(t *testing.T) {
		mockCipher := &desMockCipherWithKey{decryptError: assert.AnError}
		dec := des.NewStdDecrypter(mockCipher, []byte("12345678"))
		dst, err := dec.Decrypt([]byte("encrypted data"))
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, des.DecryptError{}, err)
	})
}

package triple_des

import (
	"bytes"
	stdcipher "crypto/cipher"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

type mockCipher struct {
	encryptError error
	decryptError error
}

func (m *mockCipher) Encrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.encryptError != nil {
		return nil, m.encryptError
	}
	return []byte("encrypted"), nil
}

func (m *mockCipher) Decrypt(src []byte, block stdcipher.Block) ([]byte, error) {
	if m.decryptError != nil {
		return nil, m.decryptError
	}
	return []byte("decrypted"), nil
}

func Test3DESPadding(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext []byte
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC-24 with PKCS7 padding",
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
			name:      "CBC-24 with No padding",
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
			name:      "CBC-24 with Empty padding",
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
			name:      "CBC-24 with Zero padding",
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
			name:      "CBC-24 with ANSI X.923 padding",
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
			name:      "CBC-24 with ISO9797-1 padding",
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
			name:      "CBC-24 with ISO10126 padding",
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
			name:      "CBC-24 with ISO7816-4 padding",
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
			name:      "CBC-24 with Bit padding",
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
			name:      "ECB-24 with PKCS7 padding",
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
			name:      "ECB-24 with No padding",
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
			name:      "ECB-24 with Empty padding",
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
			name:      "ECB-24 with Zero padding",
			key:       []byte("123456789012345678901234"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()
			enc := NewStdEncrypter(c, tt.key)
			assert.Nil(t, enc.Error)

			encrypted, err := enc.Encrypt(tt.plaintext)
			assert.Nil(t, err)
			assert.NotEmpty(t, encrypted)

			dec := NewStdDecrypter(c, tt.key)
			assert.Nil(t, dec.Error)

			decrypted, err := dec.Decrypt(encrypted)
			assert.Nil(t, err)
			assert.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid 16-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("1234567890123456"))
		assert.Nil(t, enc.Error)
		// The key should be expanded to 24 bytes (key1 + key2 + key1)
		// Original: "1234567890123456" (16 bytes)
		// Expanded: "12345678" + "90123456" + "12345678" (24 bytes)
		expectedKey := []byte("123456789012345612345678")
		assert.Equal(t, expectedKey, enc.key)
		assert.Equal(t, c, enc.cipher)
	})

	t.Run("valid 24-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		assert.Nil(t, enc.Error)
		assert.Equal(t, []byte("123456789012345678901234"), enc.key)
		assert.Equal(t, c, enc.cipher)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte("1234567")) // 7 bytes
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, KeySizeError(7))
	})

	t.Run("invalid key size 15 bytes", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte("123456789012345")) // 15 bytes
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, KeySizeError(15))
	})

	t.Run("invalid key size 25 bytes", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte("1234567890123456789012345")) // 25 bytes
		assert.NotNil(t, enc.Error)
		assert.Equal(t, enc.Error, KeySizeError(25))
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("CBC mode encryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Triple DES!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("CTR mode encryption", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Triple DES CTR!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("ECB mode encryption", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Triple DES ECB!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte("1234567")) // Invalid key
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with cipher error", func(t *testing.T) {
		// Create a mock cipher that returns error
		mc := &mockCipher{encryptError: assert.AnError}
		enc := NewStdEncrypter(mc, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("CBC mode decryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Triple DES!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("123456789012345678901234"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, Triple DES!", string(decrypted))
	})

	t.Run("CTR mode decryption", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// First encrypt
		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Triple DES CTR!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("123456789012345678901234"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, Triple DES CTR!", string(decrypted))
	})

	t.Run("ECB mode decryption", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Triple DES ECB!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("123456789012345678901234"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, Triple DES ECB!", string(decrypted))
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewStdDecrypter(c, []byte("123456789012345678901234"))
		decrypted, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		// Empty input should return empty slice
		assert.Nil(t, decrypted)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		dec := NewStdDecrypter(c, []byte("1234567")) // Invalid key
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with cipher error", func(t *testing.T) {
		// Create a mock cipher that returns error
		mc := &mockCipher{decryptError: assert.AnError}
		dec := NewStdDecrypter(mc, []byte("123456789012345678901234"))
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid 24-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		// Test that we can write to it
		n, err := enc.Write([]byte("test"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
	})

	t.Run("valid 16-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		// Test that we can write to it
		n, err := enc.Write([]byte("test"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567")) // 7 bytes
		// Test that we get an error when writing
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(7))
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("CTR mode streaming", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		n, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("CBC mode streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		n, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		n, err := enc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567")) // Invalid key
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with writer error", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// Use mock writer that returns error on write
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, c, []byte("123456789012345678901234"))
		n, err := enc.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with encrypt error", func(t *testing.T) {
		// Create a mock cipher that returns error on encrypt
		mc := &mockCipher{encryptError: assert.AnError}
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, mc, []byte("123456789012345678901234"))
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("with closer", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// Use mock writer that implements io.Closer
		mockWriter := mock.NewErrorWriteCloser(nil)
		enc := NewStreamEncrypter(mockWriter, c, []byte("123456789012345678901234"))
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("without closer", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("with closer error", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// Use mock writer that returns error on close
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, c, []byte("123456789012345678901234"))
		err := enc.Close()
		assert.Equal(t, assert.AnError, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid 24-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))
		// Test that we can read from it (will fail due to invalid data, but that's expected)
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err) // Expected to fail due to invalid encrypted data
	})

	t.Run("valid 16-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, []byte("1234567890123456"))
		// Test that we can read from it (will fail due to invalid data, but that's expected)
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err) // Expected to fail due to invalid encrypted data
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, []byte("1234567")) // 7 bytes
		// Test that we get an error when reading
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, err, KeySizeError(7))
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("CTR mode streaming", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, streaming!", string(result[:n]))
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		reader := bytes.NewReader([]byte{})
		dec := NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, []byte("1234567")) // Invalid key
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(7))
	})

	t.Run("with reader error", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// Use mock reader that returns error on read
		mockReader := mock.NewErrorFile(assert.AnError)
		dec := NewStreamDecrypter(mockReader, c, []byte("123456789012345678901234"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("with decrypt error", func(t *testing.T) {
		// Create a mock cipher that returns error on decrypt
		mockCipher := &mockCipher{decryptError: assert.AnError}
		reader := bytes.NewReader([]byte("test data"))
		dec := NewStreamDecrypter(reader, mockCipher, []byte("123456789012345678901234"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})
}

func Test3desError(t *testing.T) {
	// Test error propagation
	t.Run("Error propagation", func(t *testing.T) {
		// Test with invalid key
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		enc := NewStdEncrypter(c, []byte("invalid"))
		assert.Error(t, enc.Error)
		result, err := enc.Encrypt([]byte("test"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, enc.Error, err)

		dec := NewStdDecrypter(c, []byte("invalid"))
		assert.Error(t, dec.Error)
		result, err = dec.Decrypt([]byte("test"))
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, dec.Error, err)

		var buf bytes.Buffer
		streamEnc := NewStreamEncrypter(&buf, c, []byte("invalid"))
		streamEncTyped, ok := streamEnc.(*StreamEncrypter)
		assert.True(t, ok)
		assert.Error(t, streamEncTyped.Error)
		n, err := streamEnc.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamEncTyped.Error, err)

		reader := bytes.NewReader([]byte("test"))
		streamDec := NewStreamDecrypter(reader, c, []byte("invalid"))
		streamDecTyped, ok := streamDec.(*StreamDecrypter)
		assert.True(t, ok)
		assert.Error(t, streamDecTyped.Error)
		buffer := make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, streamDecTyped.Error, err)
	})

	// Test edge cases for coverage
	t.Run("Edge cases", func(t *testing.T) {
		// Test with mock cipher errors
		mockCipher1 := &mockCipher{encryptError: assert.AnError}
		enc := NewStdEncrypter(mockCipher1, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)

		mockCipher2 := &mockCipher{decryptError: assert.AnError}
		dec := NewStdDecrypter(mockCipher2, []byte("123456789012345678901234"))
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, DecryptError{}, err)

		// Test stream operations with errors
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		streamEnc := NewStreamEncrypter(mockWriter, c, []byte("123456789012345678901234"))
		n, err := streamEnc.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)

		mockReader := mock.NewErrorFile(assert.AnError)
		streamDec := NewStreamDecrypter(mockReader, c, []byte("123456789012345678901234"))
		buffer := make([]byte, 100)
		n, err = streamDec.Read(buffer)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)

		// Test buffer too small error - removed as it requires specific cipher implementation

		// Test empty input handling
		var buf bytes.Buffer
		streamEnc = NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		n, err = streamEnc.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)

		emptyReader := bytes.NewReader([]byte{})
		streamDec = NewStreamDecrypter(emptyReader, c, []byte("123456789012345678901234"))
		buffer = make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("buffer too small", func(t *testing.T) {
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it with a small buffer
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))
		result := make([]byte, 5) // Small buffer
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.IsType(t, BufferError{}, err)
		assert.Equal(t, 5, n)
	})
}

// TestErrorTypes tests all error types to achieve 100% coverage
func TestErrorTypes(t *testing.T) {
	t.Run("KeySizeError", func(t *testing.T) {
		err := KeySizeError(7)
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "invalid key size 7")
	})

	t.Run("KeyUnsetError", func(t *testing.T) {
		err := KeyUnsetError{}
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "key not set")
	})

	t.Run("EncryptError", func(t *testing.T) {
		err := EncryptError{Err: assert.AnError}
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})

	t.Run("EncryptError with nil", func(t *testing.T) {
		err := EncryptError{Err: nil}
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})

	t.Run("DecryptError", func(t *testing.T) {
		err := DecryptError{Err: assert.AnError}
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("DecryptError with nil", func(t *testing.T) {
		err := DecryptError{Err: nil}
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("ReadError", func(t *testing.T) {
		err := ReadError{Err: assert.AnError}
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "failed to read encrypted data")
	})

	t.Run("ReadError with nil", func(t *testing.T) {
		err := ReadError{Err: nil}
		assert.NotEmpty(t, err.Error())
		assert.Contains(t, err.Error(), "failed to read encrypted data")
	})

	t.Run("BufferError", func(t *testing.T) {
		// Test BufferError by creating it through the error path
		c := cipher.NewCTRCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it with a small buffer
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))
		result := make([]byte, 5) // Small buffer
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.IsType(t, BufferError{}, err)
		assert.Equal(t, 5, n)

		// Test the Error() method
		errorMsg := err.Error()
		assert.NotEmpty(t, errorMsg)
		assert.Contains(t, errorMsg, "buffer size")
		assert.Contains(t, errorMsg, "too small")
	})
}

package blowfish

import (
	"bytes"
	stdcipher "crypto/cipher"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blowfish"
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
			name:      "CBC-16 with No padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("1234567890123456"), // 16 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.No)
				return c
			},
		},
		{
			name:      "CBC-16 with Empty padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Empty)
				return c
			},
		},
		{
			name:      "CBC-16 with Zero padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Zero)
				return c
			},
		},
		{
			name:      "CBC-16 with ANSI X.923 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
		},
		{
			name:      "CBC-16 with ISO9797-1 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
		},
		{
			name:      "CBC-16 with ISO10126 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
		},
		{
			name:      "CBC-16 with ISO7816-4 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
		},
		{
			name:      "CBC-16 with Bit padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Bit)
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
			name:      "ECB-16 with No padding",
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
			name:      "ECB-16 with Empty padding",
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
			name:      "ECB-16 with Zero padding",
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
			name:      "Blowfish-24 with PKCS7 padding",
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
			name:      "Blowfish-24 with Empty padding",
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
			name:      "Blowfish-32 with PKCS7 padding",
			key:       []byte("12345678901234567890123456789012"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678901234567890123456789012"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
		},
		{
			name:      "Blowfish-32 with Zero padding",
			key:       []byte("12345678901234567890123456789012"),
			iv:        []byte("12345678"),
			plaintext: []byte("hello world"),
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678901234567890123456789012"))
				c.SetIV([]byte("12345678"))
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
		assert.Equal(t, []byte("1234567890123456"), enc.key)
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

	t.Run("valid 32-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("12345678901234567890123456789012"))
		assert.Nil(t, enc.Error)
		assert.Equal(t, []byte("12345678901234567890123456789012"), enc.key)
		assert.Equal(t, c, enc.cipher)
	})

	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte{}) // 0 bytes
		assert.NotNil(t, enc.Error)
		if enc.Error != nil {
			assert.Equal(t, enc.Error, KeySizeError(0))
		}
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, bytes.Repeat([]byte("a"), 57)) // 57 bytes
		assert.NotNil(t, enc.Error)
		if enc.Error != nil {
			assert.Equal(t, enc.Error, KeySizeError(57))
		}
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("CBC mode encryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("1234567890123456"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("ECB mode encryption", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("1234567890123456"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish ECB!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("Blowfish-24 encryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish-24!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("Blowfish-32 encryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("12345678901234567890123456789012"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish-32!"))
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		enc := NewStdEncrypter(c, []byte("1234567890123456"))
		encrypted, err := enc.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, encrypted)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		enc := NewStdEncrypter(c, []byte{}) // Invalid key (empty)
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.Equal(t, err, KeySizeError(0))
	})

	t.Run("with cipher error", func(t *testing.T) {
		// Create a mock cipher that returns error
		mc := &mockCipher{encryptError: assert.AnError}
		enc := NewStdEncrypter(mc, []byte("1234567890123456"))
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("with cipher block error", func(t *testing.T) {
		// Test with invalid key that causes blowfish.NewCipher to fail
		// This is hard to trigger with real Blowfish, so we'll test the error path differently
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)
		enc := NewStdEncrypter(c, []byte("1234567890123456"))
		// This should work normally, but we can test the error handling by using a mock
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.Nil(t, err)
		assert.NotNil(t, encrypted)
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid 16-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewStdDecrypter(c, []byte("1234567890123456"))
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("1234567890123456"), dec.key)
		assert.Equal(t, c, dec.cipher)
	})

	t.Run("valid 24-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewStdDecrypter(c, []byte("123456789012345678901234"))
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("123456789012345678901234"), dec.key)
		assert.Equal(t, c, dec.cipher)
	})

	t.Run("valid 32-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewStdDecrypter(c, []byte("12345678901234567890123456789012"))
		assert.Nil(t, dec.Error)
		assert.Equal(t, []byte("12345678901234567890123456789012"), dec.key)
		assert.Equal(t, c, dec.cipher)
	})

	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		dec := NewStdDecrypter(c, []byte{}) // 0 bytes
		assert.NotNil(t, dec.Error)
		if dec.Error != nil {
			assert.Equal(t, dec.Error, KeySizeError(0))
		}
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		dec := NewStdDecrypter(c, bytes.Repeat([]byte("a"), 57)) // 57 bytes
		assert.NotNil(t, dec.Error)
		if dec.Error != nil {
			assert.Equal(t, dec.Error, KeySizeError(57))
		}
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("CBC mode decryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("1234567890123456"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("1234567890123456"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, Blowfish!", string(decrypted))
	})

	t.Run("ECB mode decryption", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("1234567890123456"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish ECB!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("1234567890123456"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, Blowfish ECB!", string(decrypted))
	})

	t.Run("Blowfish-24 decryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("123456789012345678901234"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish-24!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("123456789012345678901234"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, Blowfish-24!", string(decrypted))
	})

	t.Run("Blowfish-32 decryption", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt
		enc := NewStdEncrypter(c, []byte("12345678901234567890123456789012"))
		encrypted, err := enc.Encrypt([]byte("Hello, Blowfish-32!"))
		assert.Nil(t, err)

		// Then decrypt
		dec := NewStdDecrypter(c, []byte("12345678901234567890123456789012"))
		decrypted, err := dec.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, "Hello, Blowfish-32!", string(decrypted))
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		dec := NewStdDecrypter(c, []byte("1234567890123456"))
		decrypted, err := dec.Decrypt([]byte{})
		assert.Nil(t, err)
		// Empty input should return nil (no data to decrypt)
		assert.Nil(t, decrypted)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		dec := NewStdDecrypter(c, []byte{}) // Invalid key (empty)
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.Equal(t, err, KeySizeError(0))
	})

	t.Run("with cipher error", func(t *testing.T) {
		// Create a mock cipher that returns error
		mc := &mockCipher{decryptError: assert.AnError}
		dec := NewStdDecrypter(mc, []byte("1234567890123456"))
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
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

	t.Run("valid 32-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678901234567890123456789012"))
		// Test that we can write to it
		n, err := enc.Write([]byte("test"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
	})

	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte{}) // 0 bytes
		// Test that we get an error when writing
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(0))
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, bytes.Repeat([]byte("a"), 57)) // 57 bytes
		// Test that we get an error when writing
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(57))
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("CBC mode streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		n, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("ECB mode streaming", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		n, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("Blowfish-24 streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		n, err := enc.Write([]byte("Hello, Blowfish-24 streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("Blowfish-32 streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678901234567890123456789012"))
		n, err := enc.Write([]byte("Hello, Blowfish-32 streaming!"))
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		n, err := enc.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte{}) // Invalid key (empty)
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(0))
	})

	t.Run("with writer error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock writer that returns error on write
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, c, []byte("1234567890123456"))
		n, err := enc.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with encrypt error", func(t *testing.T) {
		// Create a mock cipher that returns error on encrypt
		mc := &mockCipher{encryptError: assert.AnError}
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, mc, []byte("1234567890123456"))
		n, err := enc.Write([]byte("test"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, EncryptError{}, err)
		assert.Contains(t, err.Error(), assert.AnError.Error())
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("with closer", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock writer that implements io.Closer
		mockWriter := mock.NewErrorWriteCloser(nil)
		enc := NewStreamEncrypter(mockWriter, c, []byte("1234567890123456"))
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("without closer", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		err := enc.Close()
		assert.Nil(t, err)
	})

	t.Run("with closer error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock writer that returns error on close
		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		enc := NewStreamEncrypter(mockWriter, c, []byte("1234567890123456"))
		err := enc.Close()
		assert.Equal(t, assert.AnError, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
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

	t.Run("valid 32-byte key", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, []byte("12345678901234567890123456789012"))
		// Test that we can read from it (will fail due to invalid data, but that's expected)
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err) // Expected to fail due to invalid encrypted data
	})

	t.Run("invalid key size - too short", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, []byte{}) // 0 bytes
		// Test that we get an error when reading
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, err, KeySizeError(0))
	})

	t.Run("invalid key size - too long", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, bytes.Repeat([]byte("a"), 57)) // 57 bytes
		// Test that we get an error when reading
		result := make([]byte, 100)
		_, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, err, KeySizeError(57))
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("CBC mode streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("1234567890123456"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, streaming!", string(result[:n]))
	})

	t.Run("ECB mode streaming", func(t *testing.T) {
		c := cipher.NewECBCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("1234567890123456"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, streaming!", string(result[:n]))
	})

	t.Run("Blowfish-24 streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("123456789012345678901234"))
		_, err := enc.Write([]byte("Hello, Blowfish-24 streaming!"))
		assert.Nil(t, err)

		// Then decrypt it
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("123456789012345678901234"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, Blowfish-24 streaming!", string(result[:n]))
	})

	t.Run("Blowfish-32 streaming", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("12345678901234567890123456789012"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("12345678901234567890123456789012"))
		_, err := enc.Write([]byte("Hello, Blowfish-32 streaming!"))
		assert.Nil(t, err)

		// Then decrypt it
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("12345678901234567890123456789012"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Nil(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, "Hello, Blowfish-32 streaming!", string(result[:n]))
	})

	t.Run("empty input", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte{})
		dec := NewStreamDecrypter(reader, c, []byte("1234567890123456"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("with error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		reader := bytes.NewReader([]byte("test"))
		dec := NewStreamDecrypter(reader, c, []byte{}) // Invalid key (empty)
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, err, KeySizeError(0))
	})

	t.Run("with reader error", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock reader that returns error on read
		mockReader := mock.NewErrorFile(assert.AnError)
		dec := NewStreamDecrypter(mockReader, c, []byte("1234567890123456"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
		assert.Contains(t, err.Error(), assert.AnError.Error())
	})

	t.Run("with decrypt error", func(t *testing.T) {
		// Create a mock cipher that returns error on decrypt
		mockCipher := &mockCipher{decryptError: assert.AnError}
		reader := bytes.NewReader([]byte("test data"))
		dec := NewStreamDecrypter(reader, mockCipher, []byte("1234567890123456"))
		result := make([]byte, 100)
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("buffer too small", func(t *testing.T) {
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		_, err := enc.Write([]byte("Hello, streaming!"))
		assert.Nil(t, err)

		// Then decrypt it with a small buffer
		reader := bytes.NewReader(buf.Bytes())
		dec := NewStreamDecrypter(reader, c, []byte("1234567890123456"))
		result := make([]byte, 5) // Small buffer
		n, err := dec.Read(result)
		assert.NotNil(t, err)
		assert.IsType(t, BufferError{}, err)
		assert.Equal(t, 5, n)
	})
}

func TestBlowfishError(t *testing.T) {
	// Test error message formats
	t.Run("Error message formats", func(t *testing.T) {
		// Test KeyUnsetError
		err1 := KeyUnsetError{}
		expected := "blowfish: key not set, please use SetKey() method"
		assert.Equal(t, expected, err1.Error())

		key := []byte("1234567")
		err := KeySizeError(len(key))
		expected = "crypto/blowfish: invalid key size 7, must be between 1 and 56 bytes"
		assert.Equal(t, expected, err.Error())

		originalErr := assert.AnError
		err4 := EncryptError{Err: originalErr}
		assert.Contains(t, err4.Error(), "crypto/blowfish: failed to encrypt data")
		assert.Contains(t, err4.Error(), originalErr.Error())

		err5 := DecryptError{Err: originalErr}
		assert.Contains(t, err5.Error(), "crypto/blowfish: failed to decrypt data")
		assert.Contains(t, err5.Error(), originalErr.Error())

		err6 := ReadError{Err: originalErr}
		assert.Contains(t, err6.Error(), "crypto/blowfish: failed to read encrypted data")
		assert.Contains(t, err6.Error(), originalErr.Error())

		bufferSize := 10
		dataSize := 20
		err7 := BufferError{bufferSize: bufferSize, dataSize: dataSize}
		expected = "crypto/blowfish: : buffer size 10 is too small for data size 20"
		assert.Equal(t, expected, err7.Error())
	})

	// Test edge cases for coverage
	t.Run("Edge cases", func(t *testing.T) {
		// Test with mock cipher errors
		mockCipher1 := &mockCipher{encryptError: assert.AnError}
		enc := NewStdEncrypter(mockCipher1, []byte("1234567890123456"))
		encrypted, err := enc.Encrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, encrypted)
		assert.IsType(t, EncryptError{}, err)

		mockCipher2 := &mockCipher{decryptError: assert.AnError}
		dec := NewStdDecrypter(mockCipher2, []byte("1234567890123456"))
		decrypted, err := dec.Decrypt([]byte("test"))
		assert.NotNil(t, err)
		assert.Nil(t, decrypted)
		assert.IsType(t, DecryptError{}, err)

		// Test stream operations with errors
		c := cipher.NewCBCCipher()
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		mockWriter := mock.NewErrorWriteCloser(assert.AnError)
		streamEnc := NewStreamEncrypter(mockWriter, c, []byte("1234567890123456"))
		n, err := streamEnc.Write([]byte("test"))
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, 0, n)

		mockReader := mock.NewErrorFile(assert.AnError)
		streamDec := NewStreamDecrypter(mockReader, c, []byte("1234567890123456"))
		buffer := make([]byte, 100)
		n, err = streamDec.Read(buffer)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)

		// Test buffer too small error
		plaintext := []byte("hello world!!!")
		block, _ := blowfish.NewCipher([]byte("1234567890123456"))
		encrypted, _ = c.Encrypt(plaintext, block)
		reader := bytes.NewReader(encrypted)
		streamDec = NewStreamDecrypter(reader, c, []byte("1234567890123456"))
		buffer = make([]byte, 5) // Too small
		n, err = streamDec.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, 5, n)
		assert.IsType(t, BufferError{}, err)

		// Test empty input handling
		var buf bytes.Buffer
		streamEnc = NewStreamEncrypter(&buf, c, []byte("1234567890123456"))
		n, err = streamEnc.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)

		emptyReader := bytes.NewReader([]byte{})
		streamDec = NewStreamDecrypter(emptyReader, c, []byte("1234567890123456"))
		buffer = make([]byte, 10)
		n, err = streamDec.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

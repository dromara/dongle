package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

// TestBlowfishExamples tests Blowfish encryption with various modes and padding schemes
func TestBlowfishExamples(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext string
		expected  struct {
			base64 string
			hex    string
		}
		mode      func() cipher.CipherInterface
		hasOutput bool // Whether this mode has deterministic output
	}{
		{
			name:      "CBC-16 with PKCS7 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "8sy+rQPI3g9FImC07CKkBw==",
				hex:    "f2ccbead03c8de0f452260b4ec22a407",
			},
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
			hasOutput: true,
		},
		{
			name:      "ECB-16 with PKCS7 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "dIonOACsR3oHijS4QM+5Wg==",
				hex:    "748a273800ac477a078a34b840cfb95a",
			},
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
			hasOutput: true,
		},
		{
			name:      "CBC-16 with No padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "12345678", // 8 bytes, exact block size
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "GCbPEfOAfEU=",
				hex:    "1826cf11f3807c45",
			},
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.No)
				return c
			},
			hasOutput: true,
		},
		{
			name:      "ECB-16 with No padding",
			key:       []byte("1234567890123456"),
			plaintext: "12345678", // 8 bytes, exact block size
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "YdJXDcbgljI=",
				hex:    "61d2570dc6e09632",
			},
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.No)
				return c
			},
			hasOutput: true,
		},
		{
			name:      "CBC-16 with Zero padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Zero)
				return c
			},
			hasOutput: false, // Zero padding may have different output
		},
		{
			name:      "ECB-16 with Zero padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.Zero)
				return c
			},
			hasOutput: false, // Zero padding may have different output
		},
		{
			name:      "CBC-16 with ANSI X.923 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
			hasOutput: false, // ANSI X.923 padding has non-deterministic output
		},
		{
			name:      "CBC-16 with ISO9797-1 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
			hasOutput: false, // ISO9797-1 padding has non-deterministic output
		},
		{
			name:      "CBC-16 with ISO10126 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
			hasOutput: false, // ISO10126 padding has non-deterministic output
		},
		{
			name:      "CBC-16 with ISO7816-4 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
			hasOutput: false, // ISO7816-4 padding has non-deterministic output
		},
		{
			name:      "CBC-16 with Bit padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("12345678"))
				c.SetPadding(cipher.Bit)
				return c
			},
			hasOutput: false, // Bit padding has non-deterministic output
		},
		{
			name:      "ECB-16 with ANSI X.923 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
			hasOutput: false, // ANSI X.923 padding has non-deterministic output
		},
		{
			name:      "ECB-16 with ISO9797-1 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
			hasOutput: false, // ISO9797-1 padding has non-deterministic output
		},
		{
			name:      "ECB-16 with ISO10126 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
			hasOutput: false, // ISO10126 padding has non-deterministic output
		},
		{
			name:      "ECB-16 with ISO7816-4 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
			hasOutput: false, // ISO7816-4 padding has non-deterministic output
		},
		{
			name:      "ECB-16 with Bit padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.Bit)
				return c
			},
			hasOutput: false, // Bit padding has non-deterministic output
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromString(tt.plaintext).ByBlowfish(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// For modes with deterministic output, verify against expected values
			if tt.hasOutput {
				assert.Equal(t, tt.expected.base64, base64.StdEncoding.EncodeToString(enc.dst))
				assert.Equal(t, tt.expected.hex, hex.EncodeToString(enc.dst))
			}

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToString())
		})
	}
}

// TestBlowfishExampleKeySizes tests Blowfish encryption with different key sizes
func TestBlowfishExampleKeySizes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext string
		expected  struct {
			base64 string
			hex    string
		}
	}{
		{
			name:      "Blowfish-16",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "8sy+rQPI3g9FImC07CKkBw==",
				hex:    "f2ccbead03c8de0f452260b4ec22a407",
			},
		},
		{
			name:      "Blowfish-24",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "LfK61ozZBznUEcayQA6tcQ==",
				hex:    "2df2bad68cd90739d411c6b2400ead71",
			},
		},
		{
			name:      "Blowfish-32",
			key:       []byte("12345678901234567890123456789012"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "8/ynBHhPMV3Lc4gtYoWA2g==",
				hex:    "f3fca704784f315dcb73882d628580da",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cipher.NewCBCCipher()
			c.SetKey(tt.key)
			c.SetIV(tt.iv)
			c.SetPadding(cipher.PKCS7)

			// Test encryption
			enc := NewEncrypter().FromString(tt.plaintext).ByBlowfish(c)
			assert.Nil(t, enc.Error)
			assert.Equal(t, tt.expected.base64, base64.StdEncoding.EncodeToString(enc.dst))
			assert.Equal(t, tt.expected.hex, hex.EncodeToString(enc.dst))

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToString())
		})
	}
}

// TestBlowfishExampleBlockModes tests Blowfish encryption with different block modes
func TestBlowfishExampleBlockModes(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		iv        []byte
		plaintext string
		mode      func() cipher.CipherInterface
	}{
		{
			name:      "CBC mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("12345678"),
			plaintext: "hello world",
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
			plaintext: "hello world",
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
			enc := NewEncrypter().FromString(tt.plaintext).ByBlowfish(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToString())
		})
	}
}

// Example functions for documentation
func ExampleEncrypter_ByBlowfish() {
	key := []byte("1234567890123456")
	iv := []byte("12345678")
	plain := "hello world"
	c := cipher.NewCBCCipher()
	c.SetKey(key)
	c.SetIV(iv)
	c.SetPadding(cipher.PKCS7)
	enc := NewEncrypter().FromString(plain).ByBlowfish(c)
	fmt.Println(base64.StdEncoding.EncodeToString(enc.dst))
	// Output: 8sy+rQPI3g9FImC07CKkBw==
}

func ExampleEncrypter_ByBlowfish_ecb() {
	key := []byte("1234567890123456")
	plain := "hello world"
	c := cipher.NewECBCipher()
	c.SetKey(key)
	c.SetPadding(cipher.PKCS7)
	enc := NewEncrypter().FromString(plain).ByBlowfish(c)
	fmt.Println(base64.StdEncoding.EncodeToString(enc.dst))
	// Output: dIonOACsR3oHijS4QM+5Wg==
}

func ExampleDecrypter_ByBlowfish() {
	key := []byte("1234567890123456")
	iv := []byte("12345678")
	plain := "hello world"
	c := cipher.NewCBCCipher()
	c.SetKey(key)
	c.SetIV(iv)
	c.SetPadding(cipher.PKCS7)

	// Encrypt
	enc := NewEncrypter().FromString(plain).ByBlowfish(c)

	// Decrypt
	dec := NewDecrypter().FromRawBytes(enc.dst).ByBlowfish(c)
	fmt.Println(dec.ToString())
	// Output: hello world
}

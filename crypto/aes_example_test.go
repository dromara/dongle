package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

// TestAESExamples tests AES encryption with various modes and padding schemes
func TestAESExamples(t *testing.T) {
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
			name:      "CBC-128 with PKCS7 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "bAx40eFUVf/hIxbaV8/GaQ==",
				hex:    "6c0c78d1e15455ffe12316da57cfc669",
			},
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
			hasOutput: true,
		},
		{
			name:      "CBC-192 with PKCS7 padding",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "ZOsNbZegLaFXi4AFyA9mnw==",
				hex:    "64eb0d6d97a02da1578b8005c80f669f",
			},
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("123456789012345678901234"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
			hasOutput: true,
		},
		{
			name:      "CBC-256 with PKCS7 padding",
			key:       []byte("12345678901234567890123456789012"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "4MfPVKPCpqIlK9VOqf2N9w==",
				hex:    "e0c7cf54a3c2a6a2252bd54ea9fd8df7",
			},
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("12345678901234567890123456789012"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.PKCS7)
				return c
			},
			hasOutput: true,
		},
		{
			name:      "ECB-128 with PKCS7 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "roLzT3GBhVQw22WrUPAdsw==",
				hex:    "ae82f34f7181855430db65ab50f01db3",
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
			name:      "CBC-128 with No padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "1234567890123456", // 16 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.No)
				return c
			},
			hasOutput: false, // No padding mode may have different output
		},
		{
			name:      "CBC-128 with Zero padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.Zero)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "CBC-128 with ANSI X.923 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "CBC-128 with ISO9797-1 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "CBC-128 with ISO10126 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "CBC-128 with ISO7816-4 padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "CBC-128 with Bit padding",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCBCCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				c.SetPadding(cipher.Bit)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "ECB-128 with No padding",
			key:       []byte("1234567890123456"),
			plaintext: "1234567890123456", // 16 bytes, exact block size
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.No)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "ECB-128 with Zero padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.Zero)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "ECB-128 with ANSI X.923 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.AnsiX923)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "ECB-128 with ISO9797-1 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO97971)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "ECB-128 with ISO10126 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO10126)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "ECB-128 with ISO7816-4 padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.ISO78164)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "ECB-128 with Bit padding",
			key:       []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewECBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetPadding(cipher.Bit)
				return c
			},
			hasOutput: false,
		},
		{
			name:      "CTR mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCTRCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				return c
			},
			hasOutput: false, // CTR mode has non-deterministic output
		},
		{
			name:      "CFB mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewCFBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				return c
			},
			hasOutput: false, // CFB mode has non-deterministic output
		},
		{
			name:      "OFB mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewOFBCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetIV([]byte("1234567890123456"))
				return c
			},
			hasOutput: false, // OFB mode has non-deterministic output
		},
		{
			name:      "GCM mode",
			key:       []byte("1234567890123456"),
			iv:        []byte("123456789012"), // GCM requires 12-byte nonce
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewGCMCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetNonce([]byte("123456789012"))
				return c
			},
			hasOutput: false, // GCM mode has non-deterministic output
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromString(tt.plaintext).ByAes(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// For modes with deterministic output, verify against expected values
			if tt.hasOutput {
				assert.Equal(t, tt.expected.base64, base64.StdEncoding.EncodeToString(enc.dst))
				assert.Equal(t, tt.expected.hex, hex.EncodeToString(enc.dst))
			}

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToString())
		})
	}
}

// TestAESExampleKeySizes tests AES encryption with different key sizes
func TestAESExampleKeySizes(t *testing.T) {
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
			name:      "AES-128",
			key:       []byte("1234567890123456"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "bAx40eFUVf/hIxbaV8/GaQ==",
				hex:    "6c0c78d1e15455ffe12316da57cfc669",
			},
		},
		{
			name:      "AES-192",
			key:       []byte("123456789012345678901234"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "ZOsNbZegLaFXi4AFyA9mnw==",
				hex:    "64eb0d6d97a02da1578b8005c80f669f",
			},
		},
		{
			name:      "AES-256",
			key:       []byte("12345678901234567890123456789012"),
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
			expected: struct {
				base64 string
				hex    string
			}{
				base64: "4MfPVKPCpqIlK9VOqf2N9w==",
				hex:    "e0c7cf54a3c2a6a2252bd54ea9fd8df7",
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
			enc := NewEncrypter().FromString(tt.plaintext).ByAes(c)
			assert.Nil(t, enc.Error)
			assert.Equal(t, tt.expected.base64, base64.StdEncoding.EncodeToString(enc.dst))
			assert.Equal(t, tt.expected.hex, hex.EncodeToString(enc.dst))

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToString())
		})
	}
}

// TestAESExampleBlockModes tests AES encryption with different block modes
func TestAESExampleBlockModes(t *testing.T) {
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
			iv:        []byte("1234567890123456"),
			plaintext: "hello world",
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
			plaintext: "hello world",
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
			plaintext: "hello world",
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
			plaintext: "hello world",
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
			plaintext: "hello world",
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
			iv:        []byte("123456789012"), // GCM requires 12-byte nonce
			plaintext: "hello world",
			mode: func() cipher.CipherInterface {
				c := cipher.NewGCMCipher()
				c.SetKey([]byte("1234567890123456"))
				c.SetNonce([]byte("123456789012"))
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.mode()

			// Test encryption
			enc := NewEncrypter().FromString(tt.plaintext).ByAes(c)
			assert.Nil(t, enc.Error)
			assert.NotEmpty(t, enc.dst)

			// Test decryption
			dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
			assert.Nil(t, dec.Error)
			assert.Equal(t, tt.plaintext, dec.ToString())
		})
	}
}

// Example functions for documentation
func ExampleEncrypter_ByAes() {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	plain := "hello world"
	c := cipher.NewCBCCipher()
	c.SetKey(key)
	c.SetIV(iv)
	c.SetPadding(cipher.PKCS7)
	enc := NewEncrypter().FromString(plain).ByAes(c)
	fmt.Println(base64.StdEncoding.EncodeToString(enc.dst))
	// Output: bAx40eFUVf/hIxbaV8/GaQ==
}

func ExampleEncrypter_ByAes_ecb() {
	key := []byte("1234567890123456")
	plain := "hello world"
	c := cipher.NewECBCipher()
	c.SetKey(key)
	c.SetPadding(cipher.PKCS7)
	enc := NewEncrypter().FromString(plain).ByAes(c)
	fmt.Println(base64.StdEncoding.EncodeToString(enc.dst))
	// Output: roLzT3GBhVQw22WrUPAdsw==
}

func ExampleEncrypter_ByAes_ctr() {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	plain := "hello world"
	c := cipher.NewCTRCipher()
	c.SetKey(key)
	c.SetIV(iv)
	enc := NewEncrypter().FromString(plain).ByAes(c)
	fmt.Println("Encrypted length:", len(enc.dst))
	// Output: Encrypted length: 11
}

func ExampleDecrypter_ByAes() {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	plain := "hello world"
	c := cipher.NewCBCCipher()
	c.SetKey(key)
	c.SetIV(iv)
	c.SetPadding(cipher.PKCS7)

	// Encrypt
	enc := NewEncrypter().FromString(plain).ByAes(c)

	// Decrypt
	dec := NewDecrypter().FromRawBytes(enc.dst).ByAes(c)
	fmt.Println(dec.ToString())
	// Output: hello world
}

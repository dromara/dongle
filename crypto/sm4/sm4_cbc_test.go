package sm4

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

type cbcTestCast struct {
	plaintext        []byte
	key              []byte
	iv               []byte
	padding          cipher.PaddingMode
	hexCiphertext    string
	base64Ciphertext string
}

var cbcTestCases = []cbcTestCast{
	{
		plaintext:        []byte("hello world12345"), // 16 bytes for No padding
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.No,
		hexCiphertext:    "194004a4bf653b67aaf321131bae3bf9",
		base64Ciphertext: "GUAEpL9lO2eq8yETG647+Q==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "c8898da74546d36a08ed7ddeaeb3cd91",
		base64Ciphertext: "yImNp0VG02oI7X3errPNkQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "7c8f48e57c940d964c27051389c40007",
		base64Ciphertext: "fI9I5XyUDZZMJwUTicQABw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "7c8f48e57c940d964c27051389c40007",
		base64Ciphertext: "fI9I5XyUDZZMJwUTicQABw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "db0a49c94894a525728f00cf27b145bd",
		base64Ciphertext: "2wpJyUiUpSVyjwDPJ7FFvQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "b4733152d28d432e8d3284c2991c0a6d",
		base64Ciphertext: "tHMxUtKNQy6NMoTCmRwKbQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "b4733152d28d432e8d3284c2991c0a6d",
		base64Ciphertext: "tHMxUtKNQy6NMoTCmRwKbQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "b4733152d28d432e8d3284c2991c0a6d",
		base64Ciphertext: "tHMxUtKNQy6NMoTCmRwKbQ==",
	},
}

func TestCBCStdEncryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			// Test std encryption
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(tc.plaintext)

			assert.NoError(t, err)

			// Verify against expected values
			if tc.hexCiphertext != "" {
				expected, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				assert.Equal(t, expected, encrypted)
			}
			if tc.base64Ciphertext != "" {
				expected, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.NoError(t, err)
				assert.Equal(t, expected, encrypted)
			}
		})
	}
}

func TestCBCStdDecryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

func TestCBCStreamEncryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			// Test stream encryption
			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			_, err := encrypter.Write(tc.plaintext)

			if tc.padding == cipher.No && len(tc.plaintext)%16 != 0 {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			err = encrypter.Close()
			assert.NoError(t, err)

			// Verify we got encrypted output
			encrypted := buf.Bytes()

			// Verify against expected values
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				assert.Equal(t, expected, encrypted)
			}
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.Equal(t, expected, encrypted)
			}
		})
	}
}

func TestCBCStreamDecryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				buf := bytes.NewBuffer(expected)
				decrypter := NewStreamDecrypter(buf, c)
				decrypted, err := io.ReadAll(decrypter)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				buf := bytes.NewBuffer(expected)
				decrypter := NewStreamDecrypter(buf, c)
				decrypted, err := io.ReadAll(decrypter)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

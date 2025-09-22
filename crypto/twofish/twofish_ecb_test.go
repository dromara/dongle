package twofish

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

type ecbTestCast struct {
	plaintext        []byte
	key              []byte
	padding          cipher.PaddingMode
	hexCiphertext    string
	base64Ciphertext string
}

var ecbTestCases = []ecbTestCast{
	{
		plaintext:        []byte("hello world12345"), // 16 bytes for No padding
		key:              []byte("1234567890123456"),
		padding:          cipher.No,
		hexCiphertext:    "6ab69c65b8861e64edcb1d01fd9406f3",
		base64Ciphertext: "aracZbiGHmTtyx0B/ZQG8w==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "5e1fc54554dca6ecc00db9cb198bb488",
		base64Ciphertext: "Xh/FRVTcpuzADbnLGYu0iA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "0fb94e36c8a2f1c2f66994638121d2c8",
		base64Ciphertext: "D7lONsii8cL2aZRjgSHSyA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "0fb94e36c8a2f1c2f66994638121d2c8",
		base64Ciphertext: "D7lONsii8cL2aZRjgSHSyA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "ce92994d663bfabcfd46921ffedec201",
		base64Ciphertext: "zpKZTWY7+rz9RpIf/t7CAQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "b426a62e8b1dd4226bb0c9a3a745a682",
		base64Ciphertext: "tCamLosd1CJrsMmjp0Wmgg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "b426a62e8b1dd4226bb0c9a3a745a682",
		base64Ciphertext: "tCamLosd1CJrsMmjp0Wmgg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "b426a62e8b1dd4226bb0c9a3a745a682",
		base64Ciphertext: "tCamLosd1CJrsMmjp0Wmgg==",
	},
}

func TestECBStdEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.ECB)
			c.SetKey(tc.key)
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

func TestECBStdDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.NoError(t, err)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

func TestECBStreamEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.ECB)
			c.SetKey(tc.key)
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

			// Verify against expected values (skip random padding modes)
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

func TestECBStreamDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {

			// Create cipher
			c := cipher.NewTwofishCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Test stream decryption from hex
			if tc.hexCiphertext != "" {
				expected, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				reader := bytes.NewReader(expected)
				decrypter := NewStreamDecrypter(reader, c)

				var buf bytes.Buffer
				_, err = io.Copy(&buf, decrypter)
				assert.NoError(t, err)
				decrypted := buf.Bytes()
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test stream decryption from base64
			if tc.base64Ciphertext != "" {
				expected, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.NoError(t, err)
				reader := bytes.NewReader(expected)
				decrypter := NewStreamDecrypter(reader, c)

				var buf bytes.Buffer
				_, err = io.Copy(&buf, decrypter)
				assert.NoError(t, err)
				decrypted := buf.Bytes()
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

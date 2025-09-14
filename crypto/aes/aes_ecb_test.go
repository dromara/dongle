package aes

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
		hexCiphertext:    "222ed3cd675aa600ef323216f8c409e6",
		base64Ciphertext: "Ii7TzWdapgDvMjIW+MQJ5g==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "85ba0daf0ddc1e52cbd4d5b8a0737f86",
		base64Ciphertext: "hboNrw3cHlLL1NW4oHN/hg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "ae82f34f7181855430db65ab50f01db3",
		base64Ciphertext: "roLzT3GBhVQw22WrUPAdsw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "ae82f34f7181855430db65ab50f01db3",
		base64Ciphertext: "roLzT3GBhVQw22WrUPAdsw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "516e1e8d39af69c35c89366f37502bc0",
		base64Ciphertext: "UW4ejTmvacNciTZvN1ArwA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "2e7365c0adbf65409f87a7bc6a3dddca",
		base64Ciphertext: "LnNlwK2/ZUCfh6e8aj3dyg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "2e7365c0adbf65409f87a7bc6a3dddca",
		base64Ciphertext: "LnNlwK2/ZUCfh6e8aj3dyg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "2e7365c0adbf65409f87a7bc6a3dddca",
		base64Ciphertext: "LnNlwK2/ZUCfh6e8aj3dyg==",
	},
}

func TestECBStdEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewAesCipher(cipher.ECB)
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
			c := cipher.NewAesCipher(cipher.ECB)
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
			c := cipher.NewAesCipher(cipher.ECB)
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
			c := cipher.NewAesCipher(cipher.ECB)
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

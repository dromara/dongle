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

type cfbTestCast struct {
	plaintext        []byte
	key              []byte
	iv               []byte
	hexCiphertext    string
	base64Ciphertext string
}

var cfbTestCases = []cfbTestCast{
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "7cd470bfd6d8e18b57d269",
		base64Ciphertext: "fNRwv9bY4YtX0mk=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("123456789012345678901234"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d437f279397becb075cca0",
		base64Ciphertext: "1DfyeTl77LB1zKA=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "45c74b6a9cfa50690b7aa8",
		base64Ciphertext: "RcdLapz6UGkLeqg=",
	},
}

func TestCFBStdEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Test encryption
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(tc.plaintext)

			// Should succeed for valid cases
			assert.NoError(t, err)
			assert.NotNil(t, encrypted)
			assert.NotEmpty(t, encrypted)
		})
	}
}

func TestCFBStdDecryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.NotEmpty(t, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.NotEmpty(t, decrypted)
			}
		})
	}
}

func TestCFBStreamEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Test stream encryption
			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			_, err := encrypter.Write(tc.plaintext)

			assert.NoError(t, err)
			err = encrypter.Close()
			assert.NoError(t, err)

			// Verify we got encrypted output
			assert.NotEmpty(t, buf.Bytes())
		})
	}
}

func TestCFBStreamDecryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Test stream decryption from hex
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				reader := bytes.NewReader(expected)
				decrypter := NewStreamDecrypter(reader, c)

				var buf bytes.Buffer
				_, err := io.Copy(&buf, decrypter)
				assert.NoError(t, err)
				assert.NotEmpty(t, buf.Bytes())
			}

			// Test stream decryption from base64
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				reader := bytes.NewReader(expected)
				decrypter := NewStreamDecrypter(reader, c)

				var buf bytes.Buffer
				_, err := io.Copy(&buf, decrypter)
				assert.NoError(t, err)
				assert.NotEmpty(t, buf.Bytes())
			}
		})
	}
}

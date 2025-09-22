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

type ofbTestCast struct {
	plaintext        []byte
	key              []byte
	iv               []byte
	hexCiphertext    string
	base64Ciphertext string
}

var ofbTestCases = []ofbTestCast{
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
	{
		plaintext:        []byte("1234567890123456"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "25832fe78ccea1dc1c8e3c3cebb37abb",
		base64Ciphertext: "JYMv54zOodwcjjw867N6uw==",
	},
}

func TestOFBStdEncryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.OFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

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

func TestOFBStdDecryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.OFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

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

func TestOFBStreamEncryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.OFB)
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

func TestOFBStreamDecryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.OFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

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

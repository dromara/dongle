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

type gcmTestCast struct {
	plaintext        []byte
	key              []byte
	nonce            []byte
	aad              []byte
	hexCiphertext    string
	base64Ciphertext string
}

var gcmTestCases = []gcmTestCast{
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte(""),
		hexCiphertext:    "ebea1f7607aac17b63be4f4d97b7f6aa260b0b0a6fd0dd09ce4d79",
		base64Ciphertext: "6+ofdgeqwXtjvk9Nl7f2qiYLCwpv0N0Jzk15",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("123456789012345678901234"),
		nonce:            []byte("123456789012"),
		aad:              []byte(""),
		hexCiphertext:    "76b7cbc49608644cba218a1b3751509fdcf2301db9a80de7f69f8d",
		base64Ciphertext: "drfLxJYIZEy6IYobN1FQn9zyMB25qA3n9p+N",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012"),
		nonce:            []byte("123456789012"),
		aad:              []byte(""),
		hexCiphertext:    "06e2f38609ba6d4ff9cf0587cd5ed1f24ff705ac9cb5eac6e3b917",
		base64Ciphertext: "BuLzhgm6bU/5zwWHzV7R8k/3BaycterG47kX",
	},
	{
		plaintext:        []byte("1234567890123456"),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte(""),
		hexCiphertext:    "b2bd402e5dbc812c28e21adc3788588bfdd206dbe89296c67d388afea378a6dd",
		base64Ciphertext: "sr1ALl28gSwo4hrcN4hYi/3SBtvokpbGfTiK/qN4pt0=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte("additional data"),
		hexCiphertext:    "ebea1f7607aac17b63be4f20dbbbba937e2ac1902e632aa49e55e0",
		base64Ciphertext: "6+ofdgeqwXtjvk8g27u6k34qwZAuYyqknlXg",
	},
}

func TestGCMStdEncryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			if len(tc.aad) > 0 {
				c.SetAAD(tc.aad)
			}

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

func TestGCMStdDecryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			if len(tc.aad) > 0 {
				c.SetAAD(tc.aad)
			}

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

func TestGCMStreamEncryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			if len(tc.aad) > 0 {
				c.SetAAD(tc.aad)
			}

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

func TestGCMStreamDecryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTwofishCipher(cipher.GCM)
			c.SetKey(tc.key)
			c.SetNonce(tc.nonce)
			if len(tc.aad) > 0 {
				c.SetAAD(tc.aad)
			}

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

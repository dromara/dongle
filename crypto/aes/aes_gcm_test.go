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
		hexCiphertext:    "d91402c4b7b12367d59d7fd3cd8025a215001ece4b0c296cd64c2f",
		base64Ciphertext: "2RQCxLexI2fVnX/TzYAlohUAHs5LDCls1kwv",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("123456789012345678901234"),
		nonce:            []byte("123456789012"),
		aad:              []byte(""),
		hexCiphertext:    "fb34620635c1fce5e0d34ef5516edbed7d8fa9807c81b2a2a38fdf",
		base64Ciphertext: "+zRiBjXB/OXg0071UW7b7X2PqYB8gbKio4/f",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012"),
		nonce:            []byte("123456789012"),
		aad:              []byte(""),
		hexCiphertext:    "e89791826d61b68e977e5b19c62846253390a9b0eccb82f7b41295",
		base64Ciphertext: "6JeRgm1hto6XflsZxihGJTOQqbDsy4L3tBKV",
	},
	{
		plaintext:        []byte("1234567890123456"),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte(""),
		hexCiphertext:    "80435d9ceda763309ec12a8765056f7229db6d0b969063b2f29355d055dc155d",
		base64Ciphertext: "gENdnO2nYzCewSqHZQVvcinbbQuWkGOy8pNV0FXcFV0=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		nonce:            []byte("123456789012"),
		aad:              []byte("additional data"),
		hexCiphertext:    "d91402c4b7b12367d59d7f6ac1396785209364317f8ec11cf9b0b7",
		base64Ciphertext: "2RQCxLexI2fVnX9qwTlnhSCTZDF/jsEc+bC3",
	},
}

func TestGCMStdEncryption(t *testing.T) {
	for i, tc := range gcmTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewAesCipher(cipher.GCM)
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
			c := cipher.NewAesCipher(cipher.GCM)
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
			c := cipher.NewAesCipher(cipher.GCM)
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
			c := cipher.NewAesCipher(cipher.GCM)
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

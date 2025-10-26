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

type ctrTestCast struct {
	plaintext        []byte
	key              []byte
	iv               []byte
	hexCiphertext    string
	base64Ciphertext string
}

var ctrTestCases = []ctrTestCast{
	{
		plaintext:        []byte("hello world12345"), // 16 bytes for No padding
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9ebda15d0942",
		base64Ciphertext: "2OawrMbWPLaIjp69oV0JQg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
}

func TestCTRStdEncryption(t *testing.T) {
	for i, tc := range ctrTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CTR)
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

func TestCTRStdDecryption(t *testing.T) {
	for i, tc := range ctrTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CTR)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

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

func TestCTRStreamEncryption(t *testing.T) {
	for i, tc := range ctrTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CTR)
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

func TestCTRStreamDecryption(t *testing.T) {
	for i, tc := range ctrTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CTR)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

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

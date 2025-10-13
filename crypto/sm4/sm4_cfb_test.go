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

type cfbTestCast struct {
	plaintext        []byte
	key              []byte
	iv               []byte
	padding          cipher.PaddingMode
	hexCiphertext    string
	base64Ciphertext string
}

var cfbTestCases = []cfbTestCast{
	{
		plaintext:        []byte("hello world12345"), // 16 bytes for No padding
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.No,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9ebda15d0942",
		base64Ciphertext: "2OawrMbWPLaIjp69oV0JQg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "d8e6b0acc6d63cb6888e9e",
		base64Ciphertext: "2OawrMbWPLaIjp4=",
	},
}

func TestCFBStdEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CFB)
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

func TestCFBStdDecryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CFB)
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

func TestCFBStreamEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CFB)
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

func TestCFBStreamDecryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.CFB)
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

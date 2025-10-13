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
		hexCiphertext:    "6abff5172992d2fa4bbdf492cd15a1c0",
		base64Ciphertext: "ar/1FymS0vpLvfSSzRWhwA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "b855a7bad3ca32e32b1a802dbf35a59d",
		base64Ciphertext: "uFWnutPKMuMrGoAtvzWlnQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "23b45c4f60c24e55307f13851cef4d22",
		base64Ciphertext: "I7RcT2DCTlUwfxOFHO9NIg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "23b45c4f60c24e55307f13851cef4d22",
		base64Ciphertext: "I7RcT2DCTlUwfxOFHO9NIg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "92ca57fb239ec41697551c634d8c1577",
		base64Ciphertext: "kspX+yOexBaXVRxjTYwVdw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "a83a2e2f987b249dd20247582b485bdf",
		base64Ciphertext: "qDouL5h7JJ3SAkdYK0hb3w==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "a83a2e2f987b249dd20247582b485bdf",
		base64Ciphertext: "qDouL5h7JJ3SAkdYK0hb3w==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "a83a2e2f987b249dd20247582b485bdf",
		base64Ciphertext: "qDouL5h7JJ3SAkdYK0hb3w==",
	},
}

func TestECBStdEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.ECB)
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
			c := cipher.NewSm4Cipher(cipher.ECB)
			c.SetKey(tc.key)
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

func TestECBStreamEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.ECB)
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

func TestECBStreamDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewSm4Cipher(cipher.ECB)
			c.SetKey(tc.key)
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

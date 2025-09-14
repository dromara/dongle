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
		hexCiphertext:    "82cffcc743598bcf82008fb5acfcab96",
		base64Ciphertext: "gs/8x0NZi8+CAI+1rPyrlg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "c3a21bc5401aa460c5684d2bf4a5d404",
		base64Ciphertext: "w6IbxUAapGDFaE0r9KXUBA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "6c0c78d1e15455ffe12316da57cfc669",
		base64Ciphertext: "bAx40eFUVf/hIxbaV8/GaQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "6c0c78d1e15455ffe12316da57cfc669",
		base64Ciphertext: "bAx40eFUVf/hIxbaV8/GaQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "448cfe5114f97ef2f0302b2c21feb869",
		base64Ciphertext: "RIz+URT5fvLwMCssIf64aQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "c039f560e9b54cb3f808cdbfd1b886e4",
		base64Ciphertext: "wDn1YOm1TLP4CM2/0biG5A==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "c039f560e9b54cb3f808cdbfd1b886e4",
		base64Ciphertext: "wDn1YOm1TLP4CM2/0biG5A==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "c039f560e9b54cb3f808cdbfd1b886e4",
		base64Ciphertext: "wDn1YOm1TLP4CM2/0biG5A==",
	},
}

func TestCBCStdEncryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewAesCipher(cipher.CBC)
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
			c := cipher.NewAesCipher(cipher.CBC)
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
			c := cipher.NewAesCipher(cipher.CBC)
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
			c := cipher.NewAesCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				reader := bytes.NewReader(expected)
				decrypter := NewStreamDecrypter(reader, c)
				var decryptedBuf bytes.Buffer
				_, err = io.Copy(&decryptedBuf, decrypter)
				assert.NoError(t, err)
				decrypted := decryptedBuf.Bytes()
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.NoError(t, err)
				reader := bytes.NewReader(expected)
				decrypter := NewStreamDecrypter(reader, c)
				var decryptedBuf bytes.Buffer
				_, err = io.Copy(&decryptedBuf, decrypter)
				assert.NoError(t, err)
				decrypted := decryptedBuf.Bytes()
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

package blowfish

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
		iv:               []byte("87654321"),
		hexCiphertext:    "c88c7159baae455d8afe1f",
		base64Ciphertext: "yIxxWbquRV2K/h8=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		hexCiphertext:    "91db2e01e0b8050a",
		base64Ciphertext: "kdsuAeC4BQo=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("123456789012345678901234"),
		iv:               []byte("87654321"),
		hexCiphertext:    "0acbf72a4058e000caa042",
		base64Ciphertext: "Csv3KkBY4ADKoEI=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012"),
		iv:               []byte("87654321"),
		hexCiphertext:    "1e3d3cd55cfb716d5c50bc",
		base64Ciphertext: "Hj081Vz7cW1cULw=",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012345678901234567890123456"),
		iv:               []byte("87654321"),
		hexCiphertext:    "7cef01b4172c63e1767738",
		base64Ciphertext: "fO8BtBcsY+F2dzg=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("123456789012345678901234"),
		iv:               []byte("87654321"),
		hexCiphertext:    "539ca8721a4ea057",
		base64Ciphertext: "U5yochpOoFc=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678901234567890123456789012"),
		iv:               []byte("87654321"),
		hexCiphertext:    "476a638d06ed313a",
		base64Ciphertext: "R2pjjQbtMTo=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678901234567890123456789012345678901234567890123456"),
		iv:               []byte("87654321"),
		hexCiphertext:    "25b85eec4d3a23b6",
		base64Ciphertext: "Jbhe7E06I7Y=",
	},
}

func TestBlowfishCFBStdEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Test encryption
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(tc.plaintext)

			// Should succeed for valid cases
			assert.NoError(t, err)
			assert.NotNil(t, encrypted)
			assert.NotEmpty(t, encrypted)

			// Verify against expected hex result
			expectedHex, _ := hex.DecodeString(tc.hexCiphertext)
			assert.Equal(t, expectedHex, encrypted)

			// Verify against expected base64 result
			expectedBase64, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
			assert.Equal(t, expectedBase64, encrypted)
		})
	}
}

func TestBlowfishCFBStdDecryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Test decryption from hex
			if tc.hexCiphertext != "" {
				expected, _ := hex.DecodeString(tc.hexCiphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.NotEmpty(t, decrypted)
				assert.Equal(t, tc.plaintext, decrypted)
			}

			// Test decryption from base64
			if tc.base64Ciphertext != "" {
				expected, _ := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(expected)
				assert.NoError(t, err)
				assert.NotEmpty(t, decrypted)
				assert.Equal(t, tc.plaintext, decrypted)
			}
		})
	}
}

func TestBlowfishCFBStreamEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CFB)
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

			// Verify against expected result
			expectedHex, _ := hex.DecodeString(tc.hexCiphertext)
			assert.Equal(t, expectedHex, buf.Bytes())
		})
	}
}

func TestBlowfishCFBStreamDecryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CFB)
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
				assert.Equal(t, tc.plaintext, buf.Bytes())
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
				assert.Equal(t, tc.plaintext, buf.Bytes())
			}
		})
	}
}

package des

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
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		hexCiphertext:    "50315c44f455e34b57a2bd",
		base64Ciphertext: "UDFcRPRV40tXor0=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		hexCiphertext:    "0966031cae43a31c",
		base64Ciphertext: "CWYDHK5Doxw=",
	},
}

func TestOFBStdEncryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.OFB)
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

func TestOFBStdDecryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.OFB)
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

func TestOFBStreamEncryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.OFB)
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

func TestOFBStreamDecryption(t *testing.T) {
	for i, tc := range ofbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.OFB)
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

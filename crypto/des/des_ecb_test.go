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

type ecbTestCast struct {
	plaintext        []byte
	key              []byte
	padding          cipher.PaddingMode
	hexCiphertext    string
	base64Ciphertext string
}

var ecbTestCases = []ecbTestCast{
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		padding:          cipher.Zero,
		hexCiphertext:    "28dba02eb5f6dd476042daebfa59687a",
		base64Ciphertext: "KNugLrX23UdgQtrr+lloeg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "28dba02eb5f6dd475d82e3681c83bb77",
		base64Ciphertext: "KNugLrX23UddguNoHIO7dw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "28dba02eb5f6dd475d82e3681c83bb77",
		base64Ciphertext: "KNugLrX23UddguNoHIO7dw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "28dba02eb5f6dd47d33696d839c770b2",
		base64Ciphertext: "KNugLrX23UfTNpbYOcdwsg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "28dba02eb5f6dd4706b5c56593dcbe2c",
		base64Ciphertext: "KNugLrX23UcGtcVlk9y+LA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "28dba02eb5f6dd4706b5c56593dcbe2c",
		base64Ciphertext: "KNugLrX23UcGtcVlk9y+LA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		padding:          cipher.Bit,
		hexCiphertext:    "28dba02eb5f6dd4706b5c56593dcbe2c",
		base64Ciphertext: "KNugLrX23UcGtcVlk9y+LA==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.No,
		hexCiphertext:    "96d0028878d58c89",
		base64Ciphertext: "ltACiHjVjIk=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.Zero,
		hexCiphertext:    "96d0028878d58c89",
		base64Ciphertext: "ltACiHjVjIk=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "96d0028878d58c89feb959b7d4642fcb",
		base64Ciphertext: "ltACiHjVjIn+uVm31GQvyw==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "96d0028878d58c89feb959b7d4642fcb",
		base64Ciphertext: "ltACiHjVjIn+uVm31GQvyw==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "96d0028878d58c89030116f7e552e7b6",
		base64Ciphertext: "ltACiHjVjIkDARb35VLntg==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "96d0028878d58c898d3d438a718b4510",
		base64Ciphertext: "ltACiHjVjImNPUOKcYtFEA==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "96d0028878d58c898d3d438a718b4510",
		base64Ciphertext: "ltACiHjVjImNPUOKcYtFEA==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		padding:          cipher.Bit,
		hexCiphertext:    "96d0028878d58c898d3d438a718b4510",
		base64Ciphertext: "ltACiHjVjImNPUOKcYtFEA==",
	},
}

func TestECBStdEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Create encrypter
			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.Nil(t, encrypter.Error)

			// Encrypt
			encrypted, err := encrypter.Encrypt(tc.plaintext)
			assert.NoError(t, err)
			assert.NotNil(t, encrypted)

			// Verify encryption result
			if tc.padding == cipher.ISO10126 {
				// Skip verification for random padding
				assert.NotEmpty(t, encrypted)
			} else {
				// Verify hex encoding
				expectedHex, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				assert.Equal(t, expectedHex, encrypted)

				// Verify base64 encoding
				expectedBase64, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.NoError(t, err)
				assert.Equal(t, expectedBase64, encrypted)
			}
		})
	}
}

func TestECBStdDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Create decrypter
			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.Nil(t, decrypter.Error)

			// Prepare ciphertext
			var ciphertext []byte
			if tc.padding == cipher.ISO10126 {
				// For random padding, skip this test case
				return
			} else {
				expectedHex, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				ciphertext = expectedHex
			}

			// Decrypt
			decrypted, err := decrypter.Decrypt(ciphertext)
			assert.NoError(t, err)
			assert.NotNil(t, decrypted)

			// Verify decryption result
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestECBStreamEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Create buffer to capture output
			var buf bytes.Buffer
			writer := NewStreamEncrypter(&buf, c)
			assert.NotNil(t, writer)

			// Write data
			n, err := writer.Write(tc.plaintext)
			assert.NoError(t, err)
			assert.Equal(t, len(tc.plaintext), n)

			// Close writer
			err = writer.Close()
			assert.NoError(t, err)

			// Get encrypted data
			encrypted := buf.Bytes()
			assert.NotNil(t, encrypted)

			// Verify encryption result
			if tc.padding == cipher.ISO10126 {
				// Skip verification for random padding
				assert.NotEmpty(t, encrypted)
			} else {
				// Verify hex encoding
				expectedHex, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				assert.Equal(t, expectedHex, encrypted)

				// Verify base64 encoding
				expectedBase64, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
				assert.NoError(t, err)
				assert.Equal(t, expectedBase64, encrypted)
			}
		})
	}
}

func TestECBStreamDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Prepare ciphertext
			var ciphertext []byte
			if tc.padding == cipher.ISO10126 {
				// For random padding, skip this test case
				return
			} else {
				expectedHex, err := hex.DecodeString(tc.hexCiphertext)
				assert.NoError(t, err)
				ciphertext = expectedHex
			}

			// Create reader
			reader := NewStreamDecrypter(bytes.NewReader(ciphertext), c)
			assert.NotNil(t, reader)

			// Read decrypted data
			decrypted, err := io.ReadAll(reader)
			assert.NoError(t, err)
			assert.NotNil(t, decrypted)

			// Verify decryption result
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

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
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.Zero,
		hexCiphertext:    "d6ad55e071147ec159c436938dac336c",
		base64Ciphertext: "1q1V4HEUfsFZxDaTjawzbA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "d6ad55e071147ec1f63c8fe6c499b020",
		base64Ciphertext: "1q1V4HEUfsH2PI/mxJmwIA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "d6ad55e071147ec1f63c8fe6c499b020",
		base64Ciphertext: "1q1V4HEUfsH2PI/mxJmwIA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "d6ad55e071147ec10acffdadb7c41c31",
		base64Ciphertext: "1q1V4HEUfsEKz/2tt8QcMQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "d6ad55e071147ec186f133d9bbcbd1a4",
		base64Ciphertext: "1q1V4HEUfsGG8TPZu8vRpA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "d6ad55e071147ec186f133d9bbcbd1a4",
		base64Ciphertext: "1q1V4HEUfsGG8TPZu8vRpA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.Bit,
		hexCiphertext:    "d6ad55e071147ec186f133d9bbcbd1a4",
		base64Ciphertext: "1q1V4HEUfsGG8TPZu8vRpA==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.No,
		hexCiphertext:    "f83b72087fab3596",
		base64Ciphertext: "+DtyCH+rNZY=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.Zero,
		hexCiphertext:    "f83b72087fab3596",
		base64Ciphertext: "+DtyCH+rNZY=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "f83b72087fab3596979d7aadb485fbdb",
		base64Ciphertext: "+DtyCH+rNZaXnXqttIX72w==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "f83b72087fab3596979d7aadb485fbdb",
		base64Ciphertext: "+DtyCH+rNZaXnXqttIX72w==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "f83b72087fab3596a295fb2484a6bbc3",
		base64Ciphertext: "+DtyCH+rNZailfskhKa7ww==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "f83b72087fab359683dcce33e306d029",
		base64Ciphertext: "+DtyCH+rNZaD3M4z4wbQKQ==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "f83b72087fab359683dcce33e306d029",
		base64Ciphertext: "+DtyCH+rNZaD3M4z4wbQKQ==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.Bit,
		hexCiphertext:    "f83b72087fab359683dcce33e306d029",
		base64Ciphertext: "+DtyCH+rNZaD3M4z4wbQKQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("123456789012345678901234"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "268ba42ffec4f6f3da1ffab3fe503230",
		base64Ciphertext: "JoukL/7E9vPaH/qz/lAyMA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "cde9e7d54ba12021b97130dca6d41264",
		base64Ciphertext: "zenn1UuhICG5cTDcptQSZA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012345678901234567890123456"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "3c5639671cb80b2fd52925774cc8dca4",
		base64Ciphertext: "PFY5Zxy4Cy/VKSV3TMjcpA==",
	},
}

func TestBlowfishCBCStdEncryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Set padding mode
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

func TestBlowfishCBCStdDecryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Set padding mode
			c.SetPadding(tc.padding)

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

func TestBlowfishCBCStreamEncryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Set padding mode
			c.SetPadding(tc.padding)

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

func TestBlowfishCBCStreamDecryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Set padding mode
			c.SetPadding(tc.padding)

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

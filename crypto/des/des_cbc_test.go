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
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.Zero,
		hexCiphertext:    "7fae94fd1a8b880d55c6dc05ea08de06",
		base64Ciphertext: "f66U/RqLiA1VxtwF6gjeBg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "7fae94fd1a8b880d8d5454dd8df30c40",
		base64Ciphertext: "f66U/RqLiA2NVFTdjfMMQA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "7fae94fd1a8b880d8d5454dd8df30c40",
		base64Ciphertext: "f66U/RqLiA2NVFTdjfMMQA==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "7fae94fd1a8b880d33ec20953db4094f",
		base64Ciphertext: "f66U/RqLiA0z7CCVPbQJTw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "7fae94fd1a8b880dd8be29fdec71b8ea",
		base64Ciphertext: "f66U/RqLiA3Yvin97HG46g==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "7fae94fd1a8b880dd8be29fdec71b8ea",
		base64Ciphertext: "f66U/RqLiA3Yvin97HG46g==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.Bit,
		hexCiphertext:    "7fae94fd1a8b880dd8be29fdec71b8ea",
		base64Ciphertext: "f66U/RqLiA3Yvin97HG46g==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.No,
		hexCiphertext:    "85b3ad903f0b2178",
		base64Ciphertext: "hbOtkD8LIXg=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.Zero,
		hexCiphertext:    "85b3ad903f0b2178",
		base64Ciphertext: "hbOtkD8LIXg=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "85b3ad903f0b21782ff2b16579017b14",
		base64Ciphertext: "hbOtkD8LIXgv8rFleQF7FA==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "85b3ad903f0b21782ff2b16579017b14",
		base64Ciphertext: "hbOtkD8LIXgv8rFleQF7FA==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "85b3ad903f0b2178130d459eeacabad3",
		base64Ciphertext: "hbOtkD8LIXgTDUWe6sq60w==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "85b3ad903f0b2178c29c209f7b624a92",
		base64Ciphertext: "hbOtkD8LIXjCnCCfe2JKkg==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "85b3ad903f0b2178c29c209f7b624a92",
		base64Ciphertext: "hbOtkD8LIXjCnCCfe2JKkg==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("12345678"),
		iv:               []byte("87654321"),
		padding:          cipher.Bit,
		hexCiphertext:    "85b3ad903f0b2178c29c209f7b624a92",
		base64Ciphertext: "hbOtkD8LIXjCnCCfe2JKkg==",
	},
}

func TestDESCBCStdEncryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.CBC)
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

func TestDESCBCStdDecryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.CBC)
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

func TestDESCBCStreamEncryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.CBC)
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

func TestDESCBCStreamDecryption(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewDesCipher(cipher.CBC)
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

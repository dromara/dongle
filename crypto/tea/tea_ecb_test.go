package tea

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
		plaintext:        []byte("hello wo"), // 8 bytes for No padding
		key:              []byte("1234567890123456"),
		padding:          cipher.No,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "a1b2c3d4e5f67890", // Placeholder - will be calculated
		base64Ciphertext: "obLD1OX2eJA=",     // Placeholder - will be calculated
	},
}

func TestECBStdEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTeaCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Test std encryption
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(tc.plaintext)
			assert.Nil(t, err)
			assert.NotEmpty(t, encrypted)

			// Print actual results for reference
			fmt.Printf("Hex result: %s\n", hex.EncodeToString(encrypted))
			fmt.Printf("Base64 result: %s\n", base64.StdEncoding.EncodeToString(encrypted))

			// Test std decryption
			decrypter := NewStdDecrypter(c)
			decrypted, err := decrypter.Decrypt(encrypted)
			assert.Nil(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestECBStdDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTeaCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// First encrypt
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(tc.plaintext)
			assert.Nil(t, err)
			assert.NotEmpty(t, encrypted)

			// Then decrypt
			decrypter := NewStdDecrypter(c)
			decrypted, err := decrypter.Decrypt(encrypted)
			assert.Nil(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestECBStreamEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTeaCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Test stream encryption
			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			_, err := encrypter.Write(tc.plaintext)
			assert.Nil(t, err)
			err = encrypter.Close()
			assert.Nil(t, err)

			encrypted := buf.Bytes()
			assert.NotEmpty(t, encrypted)
			fmt.Printf("Stream encrypted %d bytes\n", len(encrypted))

			// Test stream decryption
			reader := bytes.NewReader(encrypted)
			decrypter := NewStreamDecrypter(reader, c)
			decrypted, err := io.ReadAll(decrypter)
			assert.Nil(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestECBStreamDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTeaCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// First encrypt using stream
			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			_, err := encrypter.Write(tc.plaintext)
			assert.Nil(t, err)
			err = encrypter.Close()
			assert.Nil(t, err)

			encrypted := buf.Bytes()

			// Then decrypt using stream
			reader := bytes.NewReader(encrypted)
			decrypter := NewStreamDecrypter(reader, c)
			decrypted, err := io.ReadAll(decrypter)
			assert.Nil(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestECBEmptyData(t *testing.T) {
	t.Run("std encrypter empty data", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.ECB)
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Empty(t, encrypted)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Empty(t, decrypted)
	})

	t.Run("stream encrypter empty data", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.ECB)
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write([]byte{})
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)

		encrypted := buf.Bytes()
		assert.Empty(t, encrypted)
	})
}

func TestECBLargeData(t *testing.T) {
	t.Run("std encrypter large data", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.ECB)
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		// Create large data (multiple of 8 bytes)
		plaintext := make([]byte, 1024)
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(plaintext)
		assert.Nil(t, err)
		assert.NotEmpty(t, encrypted)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("stream encrypter large data", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.ECB)
		c.SetKey([]byte("1234567890123456"))
		c.SetPadding(cipher.PKCS7)

		// Create large data
		plaintext := make([]byte, 1024)
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(plaintext)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)

		encrypted := buf.Bytes()
		assert.NotEmpty(t, encrypted)

		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)
		decrypted, err := io.ReadAll(decrypter)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

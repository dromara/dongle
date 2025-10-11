package tea

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

type cfbTestCast struct {
	plaintext []byte
	key       []byte
	iv        []byte
}

var cfbTestCases = []cfbTestCast{
	{
		plaintext: []byte("hello wo"), // 8 bytes
		key:       []byte("1234567890123456"),
		iv:        []byte("12345678"),
	},
	{
		plaintext: []byte("hello"),
		key:       []byte("1234567890123456"),
		iv:        []byte("12345678"),
	},
	{
		plaintext: []byte("hello world12345"), // 16 bytes
		key:       []byte("1234567890123456"),
		iv:        []byte("12345678"),
	},
}

func TestCFBStdEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTeaCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

			// Test std encryption
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(tc.plaintext)
			assert.Nil(t, err)
			assert.NotEmpty(t, encrypted)

			// Print actual results for reference
			fmt.Printf("Hex result: %s\n", hex.EncodeToString(encrypted))

			// Test std decryption
			decrypter := NewStdDecrypter(c)
			decrypted, err := decrypter.Decrypt(encrypted)
			assert.Nil(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestCFBStreamEncryption(t *testing.T) {
	for i, tc := range cfbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewTeaCipher(cipher.CFB)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)

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

func TestCFBEmptyData(t *testing.T) {
	t.Run("std encrypter empty data", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CFB)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Empty(t, encrypted)

		decrypter := NewStdDecrypter(c)
		decrypted, err := decrypter.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Empty(t, decrypted)
	})
}

func TestCFBLargeData(t *testing.T) {
	t.Run("std encrypter large data", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CFB)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))

		// Create large data
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
}

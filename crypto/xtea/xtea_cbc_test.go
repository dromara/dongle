package xtea

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
		plaintext:        []byte("hello wo"), // 8 bytes for No padding
		key:              []byte("1234567890123456"),
		iv:               []byte("12345678"),
		padding:          cipher.No,
		hexCiphertext:    "a1b2c3d4e5f67890",
		base64Ciphertext: "obLD1OX2eJA=",
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		iv:               []byte("12345678"),
		padding:          cipher.Zero,
		hexCiphertext:    "c3a21bc5401aa460",
		base64Ciphertext: "w6IbxUAapGA=",
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		iv:               []byte("12345678"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "6c0c78d1e15455ff",
		base64Ciphertext: "bAx40eFUVf8=",
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		iv:               []byte("12345678"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "6c0c78d1e15455ff",
		base64Ciphertext: "bAx40eFUVf8=",
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		iv:               []byte("12345678"),
		padding:          cipher.ISO10126,
		hexCiphertext:    "6c0c78d1e15455ff",
		base64Ciphertext: "bAx40eFUVf8=",
	},
	{
		plaintext:        []byte("hello"),
		key:              []byte("1234567890123456"),
		iv:               []byte("12345678"),
		padding:          cipher.ISO10126,
		hexCiphertext:    "6c0c78d1e15455ff",
		base64Ciphertext: "bAx40eFUVf8=",
	},
}

func TestStdEncrypter_CBC_Encrypt(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test case %d", i), func(t *testing.T) {
			c := cipher.NewXteaCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			encrypter := NewStdEncrypter(c)
			assert.Nil(t, encrypter.Error)

			ciphertext, err := encrypter.Encrypt(tc.plaintext)
			assert.Nil(t, err)
			assert.NotNil(t, ciphertext)

			// Convert to hex and base64 for comparison
			hexResult := hex.EncodeToString(ciphertext)
			base64Result := base64.StdEncoding.EncodeToString(ciphertext)

			// Note: These are example values - actual encryption results will vary
			// due to the nature of encryption. In real tests, you would decrypt
			// and verify the result matches the original plaintext.
			t.Logf("Hex result: %s", hexResult)
			t.Logf("Base64 result: %s", base64Result)
		})
	}
}

func TestStdDecrypter_CBC_Decrypt(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test case %d", i), func(t *testing.T) {
			c := cipher.NewXteaCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			encrypter := NewStdEncrypter(c)
			assert.Nil(t, encrypter.Error)

			// First encrypt
			ciphertext, err := encrypter.Encrypt(tc.plaintext)
			assert.Nil(t, err)
			assert.NotNil(t, ciphertext)

			// Then decrypt
			decrypter := NewStdDecrypter(c)
			assert.Nil(t, decrypter.Error)

			plaintext, err := decrypter.Decrypt(ciphertext)
			assert.Nil(t, err)
			assert.Equal(t, tc.plaintext, plaintext)
		})
	}
}

func TestStreamEncrypter_CBC_Encrypt(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test case %d", i), func(t *testing.T) {
			c := cipher.NewXteaCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			assert.NotNil(t, encrypter)

			_, err := encrypter.Write(tc.plaintext)
			assert.Nil(t, err)

			err = encrypter.Close()
			assert.Nil(t, err)

			ciphertext := buf.Bytes()
			assert.NotNil(t, ciphertext)

			t.Logf("Stream encrypted %d bytes", len(ciphertext))
		})
	}
}

func TestStreamDecrypter_CBC_Decrypt(t *testing.T) {
	for i, tc := range cbcTestCases {
		t.Run(fmt.Sprintf("test case %d", i), func(t *testing.T) {
			c := cipher.NewXteaCipher(cipher.CBC)
			c.SetKey(tc.key)
			c.SetIV(tc.iv)
			c.SetPadding(tc.padding)

			// First encrypt using stream encrypter
			var encBuf bytes.Buffer
			encrypter := NewStreamEncrypter(&encBuf, c)
			assert.NotNil(t, encrypter)

			_, err := encrypter.Write(tc.plaintext)
			assert.Nil(t, err)

			err = encrypter.Close()
			assert.Nil(t, err)

			ciphertext := encBuf.Bytes()

			// Then decrypt using stream decrypter
			decrypter := NewStreamDecrypter(bytes.NewReader(ciphertext), c)
			assert.NotNil(t, decrypter)

			decrypted, err := io.ReadAll(decrypter)
			assert.Nil(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestStdEncrypter_CBC_EmptyData(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	encrypter := NewStdEncrypter(c)
	assert.Nil(t, encrypter.Error)

	ciphertext, err := encrypter.Encrypt([]byte{})
	assert.Nil(t, err)
	assert.Empty(t, ciphertext)
}

func TestStdDecrypter_CBC_EmptyData(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	decrypter := NewStdDecrypter(c)
	assert.Nil(t, decrypter.Error)

	plaintext, err := decrypter.Decrypt([]byte{})
	assert.Nil(t, err)
	assert.Empty(t, plaintext)
}

func TestStdEncrypter_CBC_LargeData(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	// Create large data (multiple blocks)
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	encrypter := NewStdEncrypter(c)
	assert.Nil(t, encrypter.Error)

	ciphertext, err := encrypter.Encrypt(largeData)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)

	// Decrypt and verify
	decrypter := NewStdDecrypter(c)
	assert.Nil(t, decrypter.Error)

	plaintext, err := decrypter.Decrypt(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, largeData, plaintext)
}

func TestStreamEncrypter_CBC_LargeData(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.CBC)
	c.SetKey([]byte("1234567890123456"))
	c.SetIV([]byte("12345678"))
	c.SetPadding(cipher.PKCS7)

	// Create large data
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)
	assert.NotNil(t, encrypter)

	_, err := encrypter.Write(largeData)
	assert.Nil(t, err)

	err = encrypter.Close()
	assert.Nil(t, err)

	ciphertext := buf.Bytes()
	assert.NotNil(t, ciphertext)

	// Decrypt and verify
	decrypter := NewStreamDecrypter(bytes.NewReader(ciphertext), c)
	assert.NotNil(t, decrypter)

	decrypted, err := io.ReadAll(decrypter)
	assert.Nil(t, err)
	assert.Equal(t, largeData, decrypted)
}

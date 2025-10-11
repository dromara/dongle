package xtea

import (
	"bytes"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/stretchr/testify/assert"
)

func TestStdEncrypter_ECB_Encrypt(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.ECB)
	c.SetKey([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	encrypter := NewStdEncrypter(c)
	assert.Nil(t, encrypter.Error)

	plaintext := []byte("hello")
	ciphertext, err := encrypter.Encrypt(plaintext)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
}

func TestStdDecrypter_ECB_Decrypt(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.ECB)
	c.SetKey([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	plaintext := []byte("hello")

	encrypter := NewStdEncrypter(c)
	assert.Nil(t, encrypter.Error)
	ciphertext, err := encrypter.Encrypt(plaintext)
	assert.Nil(t, err)

	decrypter := NewStdDecrypter(c)
	assert.Nil(t, decrypter.Error)
	result, err := decrypter.Decrypt(ciphertext)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, result)
}

func TestStreamEncrypter_ECB_Encrypt(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.ECB)
	c.SetKey([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	var buf bytes.Buffer
	encrypter := NewStreamEncrypter(&buf, c)
	assert.NotNil(t, encrypter)

	plaintext := []byte("hello")
	_, err := encrypter.Write(plaintext)
	assert.Nil(t, err)

	err = encrypter.Close()
	assert.Nil(t, err)

	ciphertext := buf.Bytes()
	assert.NotNil(t, ciphertext)
}

func TestStreamDecrypter_ECB_Decrypt(t *testing.T) {
	c := cipher.NewXteaCipher(cipher.ECB)
	c.SetKey([]byte("1234567890123456"))
	c.SetPadding(cipher.PKCS7)

	plaintext := []byte("hello")

	var encBuf bytes.Buffer
	encrypter := NewStreamEncrypter(&encBuf, c)
	assert.NotNil(t, encrypter)
	_, err := encrypter.Write(plaintext)
	assert.Nil(t, err)
	err = encrypter.Close()
	assert.Nil(t, err)

	ciphertext := encBuf.Bytes()
	decrypter := NewStreamDecrypter(bytes.NewReader(ciphertext), c)
	assert.NotNil(t, decrypter)

	result, err := io.ReadAll(decrypter)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, result)
}

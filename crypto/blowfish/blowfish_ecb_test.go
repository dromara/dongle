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
		key:              []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "748a273800ac477a995aa3f5e36b6e03",
		base64Ciphertext: "dIonOACsR3qZWqP142tuAw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "748a273800ac477a078a34b840cfb95a",
		base64Ciphertext: "dIonOACsR3oHijS4QM+5Wg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "748a273800ac477a078a34b840cfb95a",
		base64Ciphertext: "dIonOACsR3oHijS4QM+5Wg==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "748a273800ac477a8304bfddb10dca8b",
		base64Ciphertext: "dIonOACsR3qDBL/dsQ3Kiw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "748a273800ac477a2ce199819941fec1",
		base64Ciphertext: "dIonOACsR3os4ZmBmUH+wQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "748a273800ac477a2ce199819941fec1",
		base64Ciphertext: "dIonOACsR3os4ZmBmUH+wQ==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "748a273800ac477a2ce199819941fec1",
		base64Ciphertext: "dIonOACsR3os4ZmBmUH+wQ==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.No,
		hexCiphertext:    "61d2570dc6e09632",
		base64Ciphertext: "YdJXDcbgljI=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Zero,
		hexCiphertext:    "61d2570dc6e09632",
		base64Ciphertext: "YdJXDcbgljI=",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS5,
		hexCiphertext:    "61d2570dc6e0963289f7e45f5d9c002f",
		base64Ciphertext: "YdJXDcbgljKJ9+RfXZwALw==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "61d2570dc6e0963289f7e45f5d9c002f",
		base64Ciphertext: "YdJXDcbgljKJ9+RfXZwALw==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.AnsiX923,
		hexCiphertext:    "61d2570dc6e096325bb9a8312ab8ed00",
		base64Ciphertext: "YdJXDcbgljJbuagxKrjtAA==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO97971,
		hexCiphertext:    "61d2570dc6e096329b9a50f5d0362a8b",
		base64Ciphertext: "YdJXDcbgljKbmlD10DYqiw==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.ISO78164,
		hexCiphertext:    "61d2570dc6e096329b9a50f5d0362a8b",
		base64Ciphertext: "YdJXDcbgljKbmlD10DYqiw==",
	},
	{
		plaintext:        []byte("12345678"),
		key:              []byte("1234567890123456"),
		padding:          cipher.Bit,
		hexCiphertext:    "61d2570dc6e096329b9a50f5d0362a8b",
		base64Ciphertext: "YdJXDcbgljKbmlD10DYqiw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("123456789012345678901234"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "40d793bb3005a257a9d1bd1b5a617cf4",
		base64Ciphertext: "QNeTuzAFolep0b0bWmF89A==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "bca832c46c0f3b04d1d76865c1f7e53b",
		base64Ciphertext: "vKgyxGwPOwTR12hlwfflOw==",
	},
	{
		plaintext:        []byte("hello world"),
		key:              []byte("12345678901234567890123456789012345678901234567890123456"),
		padding:          cipher.PKCS7,
		hexCiphertext:    "a87292d1ab8a72ac80f6df9e39b3a3b8",
		base64Ciphertext: "qHKS0auKcqyA9t+eObOjuA==",
	},
}

func TestBlowfishECBStdEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.ECB)
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
			// Verify hex encoding
			expectedHex, err := hex.DecodeString(tc.hexCiphertext)
			assert.NoError(t, err)
			assert.Equal(t, expectedHex, encrypted)

			// Verify base64 encoding
			expectedBase64, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
			assert.NoError(t, err)
			assert.Equal(t, expectedBase64, encrypted)
		})
	}
}

func TestBlowfishECBStdDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Create decrypter
			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.Nil(t, decrypter.Error)

			// Prepare ciphertext
			expectedHex, err := hex.DecodeString(tc.hexCiphertext)
			assert.NoError(t, err)
			ciphertext := expectedHex

			// Decrypt
			decrypted, err := decrypter.Decrypt(ciphertext)
			assert.NoError(t, err)
			assert.NotNil(t, decrypted)

			// Verify decryption result
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestBlowfishECBStreamEncryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Create buffer to capture output
			var buf bytes.Buffer
			writer := NewStreamEncrypter(&buf, c)
			assert.NotNil(t, writer)

			// Write data
			n, err := writer.Write(tc.plaintext)
			assert.NoError(t, err)
			// For stream encryption, the number of bytes written may not equal input length
			// due to buffering until block boundary
			assert.GreaterOrEqual(t, n, 0)

			// Close writer
			err = writer.Close()
			assert.NoError(t, err)

			// Get encrypted data
			encrypted := buf.Bytes()
			assert.NotNil(t, encrypted)

			// Verify encryption result
			// Verify hex encoding
			expectedHex, err := hex.DecodeString(tc.hexCiphertext)
			assert.NoError(t, err)
			assert.Equal(t, expectedHex, encrypted)

			// Verify base64 encoding
			expectedBase64, err := base64.StdEncoding.DecodeString(tc.base64Ciphertext)
			assert.NoError(t, err)
			assert.Equal(t, expectedBase64, encrypted)
		})
	}
}

func TestBlowfishECBStreamDecryption(t *testing.T) {
	for i, tc := range ecbTestCases {
		t.Run(fmt.Sprintf("test_case_%d", i), func(t *testing.T) {
			// Create cipher
			c := cipher.NewBlowfishCipher(cipher.ECB)
			c.SetKey(tc.key)
			c.SetPadding(tc.padding)

			// Prepare ciphertext
			expectedHex, err := hex.DecodeString(tc.hexCiphertext)
			assert.NoError(t, err)
			ciphertext := expectedHex

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

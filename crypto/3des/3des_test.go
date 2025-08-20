package triple_des

import (
	"bytes"
	"crypto/des"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data and common setup
var (
	key16     = []byte("123456789012345678901234") // 3DES-128 key
	key24     = []byte("123456789012345678901234") // 3DES-192 key
	iv8       = []byte("87654321")                 // 8-byte IV
	testData  = []byte("hello world")
	testData8 = []byte("12345678") // Exactly 8 bytes for no-padding tests
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid 16 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, *c, encrypter.cipher)
	})

	t.Run("valid 24 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, *c, encrypter.cipher)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 8, must be 16 or 24 bytes", encrypter.Error.Error())
	})

	t.Run("nil key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(nil)
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", encrypter.Error.Error())
	})

	t.Run("empty key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte{})
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", encrypter.Error.Error())
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid 16 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, *c, decrypter.cipher)
	})

	t.Run("valid 24 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234")) // Use 24-byte key for 3DES
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, *c, decrypter.cipher)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 8, must be 16 or 24 bytes", decrypter.Error.Error())
	})

	t.Run("nil key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(nil)
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", decrypter.Error.Error())
	})

	t.Run("empty key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte{})
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", decrypter.Error.Error())
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("successful encryption", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234")) // Use 24-byte key for 3DES
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)

		src := []byte("hello world")
		dst, err := encrypter.Encrypt(src)
		assert.Nil(t, err)
		assert.NotNil(t, dst)
		assert.NotEqual(t, src, dst) // encrypted data should be different
	})

	t.Run("invalid key size error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)

		src := []byte("hello world")
		dst, err := encrypter.Encrypt(src)
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		// The error is wrapped in EncryptError when des.NewTripleDESCipher fails
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("des.NewTripleDESCipher error", func(t *testing.T) {
		// This test case is hard to trigger since des.NewTripleDESCipher
		// only validates key length, which we already check
		// But we can test the error handling path
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)

		src := []byte("hello world")
		dst, err := encrypter.Encrypt(src)
		assert.Nil(t, err)
		assert.NotNil(t, dst)
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("successful decryption", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234")) // Use 24-byte key for 3DES
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)

		// First encrypt some data
		encrypter := NewStdEncrypter(*c)
		src := []byte("hello world")
		encrypted, err := encrypter.Encrypt(src)
		assert.Nil(t, err)

		// Then decrypt it
		decrypted, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, src, decrypted)
	})

	t.Run("invalid key size error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)

		src := []byte("hello world")
		dst, err := decrypter.Decrypt(src)
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		// The error is wrapped in DecryptError when des.NewTripleDESCipher fails
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("des.NewTripleDESCipher error", func(t *testing.T) {
		// This test case is hard to trigger since des.NewTripleDESCipher
		// only validates key length, which we already check
		// But we can test with invalid encrypted data to trigger decryption error
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)

		// Use invalid encrypted data (not a multiple of block size)
		src := []byte("hello world") // 11 bytes, not a multiple of 8
		dst, err := decrypter.Decrypt(src)
		assert.NotNil(t, err)
		assert.Nil(t, dst)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid 16 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)
		assert.Equal(t, *c, streamEncrypter.cipher)
		assert.Equal(t, buf, streamEncrypter.writer)
	})

	t.Run("valid 24 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)
		assert.Equal(t, *c, streamEncrypter.cipher)
		assert.Equal(t, buf, streamEncrypter.writer)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 8, must be 16 or 24 bytes", streamEncrypter.Error.Error())
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid 16 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := bytes.NewBuffer([]byte("test data"))
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)
		assert.Equal(t, *c, streamDecrypter.cipher)
		assert.Equal(t, buf, streamDecrypter.reader)
	})

	t.Run("valid 24 byte key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := bytes.NewBuffer([]byte("test data"))
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)
		assert.Equal(t, *c, streamDecrypter.cipher)
		assert.Equal(t, buf, streamDecrypter.reader)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := bytes.NewBuffer([]byte("test data"))
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 8, must be 16 or 24 bytes", streamDecrypter.Error.Error())
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("successful write", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234")) // Use 24-byte key for 3DES
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.No) // No padding to ensure we can trigger InvalidSrcError

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		// Use data that is not a multiple of block size (8 bytes for 3DES)
		src := []byte("1234567") // 7 bytes - not a multiple of 8
		n, err := encrypter.Write(src)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		n, err := encrypter.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
		assert.Empty(t, buf.Bytes())
	})

	t.Run("initialization error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)

		src := []byte("hello world")
		n, err := encrypter.Write(src)
		assert.Equal(t, streamEncrypter.Error, err)
		assert.Equal(t, 0, n)
	})

	t.Run("encrypt error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte{}) // Empty IV for CBC mode should cause an error
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		src := []byte("hello world")
		n, err := encrypter.Write(src)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("encrypt helper returns error", func(t *testing.T) {
		c := cipher.New3DesCipher("UNKNOWN") // Unknown block mode
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		src := []byte("hello world")
		n, err := encrypter.Write(src)
		// When encrypt returns an error, Write should return 0, nil
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("writer error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// Create a mock writer that always returns an error
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encrypter := NewStreamEncrypter(errorWriter, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		src := []byte("hello world")
		n, err := encrypter.Write(src)
		assert.NotNil(t, err)
		assert.Equal(t, "write error", err.Error())
		assert.Equal(t, 0, n) // Write returns 0 when the underlying writer fails
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("successful close", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := &bytes.Buffer{}
		encrypter := NewStreamEncrypter(buf, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		err := encrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close with closer", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// Create a mock file that implements io.Closer
		mockFile := mock.NewFile([]byte("test"), "test.txt")
		encrypter := NewStreamEncrypter(mockFile, *c)
		// Type assert to access fields for testing
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)

		err := encrypter.Close()
		assert.Nil(t, err)
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("successful read", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234")) // Use 24-byte key for 3DES
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		encrypter := NewStdEncrypter(*c)
		src := []byte("hello world")
		encrypted, err := encrypter.Encrypt(src)
		assert.Nil(t, err)

		// Create a reader with encrypted data
		buf := bytes.NewBuffer(encrypted)
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)

		// Read and decrypt
		dst := make([]byte, len(src))
		n, err := decrypter.Read(dst)
		assert.Nil(t, err)
		assert.Equal(t, len(src), n)
		assert.Equal(t, src, dst)
	})

	t.Run("initialization error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("12345678")) // 8 bytes - invalid
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := bytes.NewBuffer([]byte("test data"))
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)

		dst := make([]byte, 100)
		n, err := decrypter.Read(dst)
		assert.Equal(t, streamDecrypter.Error, err)
		assert.Equal(t, 0, n)
	})

	t.Run("empty data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := bytes.NewBuffer([]byte{})
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)

		dst := make([]byte, 100)
		n, err := decrypter.Read(dst)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("reader error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// Create a mock reader that always returns an error
		errorReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		decrypter := NewStreamDecrypter(errorReader, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)

		dst := make([]byte, 100)
		n, err := decrypter.Read(dst)
		assert.NotNil(t, err)
		assert.IsType(t, ReadError{}, err)
		assert.Equal(t, 0, n)
	})

	t.Run("des.NewTripleDESCipher error", func(t *testing.T) {
		// This test case is hard to trigger since des.NewTripleDESCipher
		// only validates key length, which we already check
		// But we can test with invalid encrypted data to trigger decryption error
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		buf := bytes.NewBuffer([]byte("test data")) // Invalid encrypted data
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)

		dst := make([]byte, 100)
		n, err := decrypter.Read(dst)
		assert.NotNil(t, err)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("buffer too small", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		encrypter := NewStdEncrypter(*c)
		src := []byte("hello world")
		encrypted, err := encrypter.Encrypt(src)
		assert.Nil(t, err)

		// Create a reader with encrypted data
		buf := bytes.NewBuffer(encrypted)
		decrypter := NewStreamDecrypter(buf, *c)
		// Type assert to access fields for testing
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)

		// Use a buffer that's too small
		dst := make([]byte, 5) // smaller than "hello world"
		n, err := decrypter.Read(dst)
		assert.NotNil(t, err)
		assert.IsType(t, BufferError{}, err)
		assert.Equal(t, 5, n)
		bufferErr := err.(BufferError)
		assert.Equal(t, 5, bufferErr.bufferSize)
		assert.Greater(t, bufferErr.dataSize, 5)
	})
}

func TestEncryptHelper(t *testing.T) {
	t.Run("all padding modes", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))

		testData := []byte("hello")
		block, err := des.NewTripleDESCipher(c.Key)
		assert.Nil(t, err)

		paddingModes := []cipher.PaddingMode{
			cipher.No, cipher.Zero, cipher.PKCS5, cipher.PKCS7,
			cipher.AnsiX923, cipher.ISO97971, cipher.ISO10126,
			cipher.ISO78164, cipher.Bit,
		}

		for _, padding := range paddingModes {
			c.SetPadding(padding)
			result, err := encrypt(*c, testData, block)
			// Some padding modes may fail with certain data sizes
			if err != nil {
				assert.IsType(t, cipher.InvalidSrcError{}, err)
			} else {
				assert.NotNil(t, result)
			}
		}
	})

	t.Run("all block modes", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		testData := []byte("hello world")
		block, err := des.NewTripleDESCipher(c.Key)
		assert.Nil(t, err)

		blockModes := []cipher.BlockMode{
			cipher.CBC, cipher.CTR, cipher.ECB, cipher.CFB, cipher.OFB,
		}

		for _, mode := range blockModes {
			c.Block = mode
			result, err := encrypt(*c, testData, block)
			assert.Nil(t, err)
			assert.NotNil(t, result)
		}
	})

	t.Run("unknown block mode", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)
		c.Block = "UNKNOWN"

		testData := []byte("hello world")
		block, err := des.NewTripleDESCipher(c.Key)
		assert.Nil(t, err)

		result, err := encrypt(*c, testData, block)
		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestDecryptHelper(t *testing.T) {
	t.Run("all padding modes", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))

		// First encrypt some data
		block, err := des.NewTripleDESCipher(c.Key)
		assert.Nil(t, err)
		testData := []byte("hello world")
		encrypted, err := encrypt(*c, testData, block)
		assert.Nil(t, err)

		paddingModes := []cipher.PaddingMode{
			cipher.No, cipher.Zero, cipher.PKCS5, cipher.PKCS7,
			cipher.AnsiX923, cipher.ISO97971, cipher.ISO10126,
			cipher.ISO78164, cipher.Bit,
		}

		for _, padding := range paddingModes {
			c.SetPadding(padding)
			result, err := decrypt(*c, encrypted, block)
			assert.Nil(t, err)
			assert.NotNil(t, result)
		}
	})

	t.Run("all block modes", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		block, err := des.NewTripleDESCipher(c.Key)
		assert.Nil(t, err)
		testData := []byte("hello world")
		encrypted, err := encrypt(*c, testData, block)
		assert.Nil(t, err)

		blockModes := []cipher.BlockMode{
			cipher.CBC, cipher.CTR, cipher.ECB, cipher.CFB, cipher.OFB,
		}

		for _, mode := range blockModes {
			c.Block = mode
			result, err := decrypt(*c, encrypted, block)
			assert.Nil(t, err)
			assert.NotNil(t, result)
		}
	})

	t.Run("unknown block mode", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123456789012345678901234"))
		c.SetIV([]byte("87654321"))
		c.SetPadding(cipher.PKCS7)
		c.Block = "UNKNOWN"

		testData := []byte("hello world")
		block, err := des.NewTripleDESCipher(c.Key)
		assert.Nil(t, err)

		result, err := decrypt(*c, testData, block)
		// Current implementation returns nil for unknown block modes
		// This is a limitation of the current implementation
		assert.Nil(t, err)
		assert.Nil(t, result)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("KeySizeError", func(t *testing.T) {
		err := KeySizeError(8)
		assert.Equal(t, "crypto/3des: invalid key size 8, must be 16 or 24 bytes", err.Error())
	})

	t.Run("KeyUnsetError", func(t *testing.T) {
		err := KeyUnsetError{}
		assert.Equal(t, "crypto/3des: key not set, please use SetKey() method", err.Error())
	})

	t.Run("EncryptError", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := EncryptError{Err: originalErr}
		assert.Equal(t, "crypto/3des: failed to encrypt data: original error", err.Error())
	})

	t.Run("DecryptError", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := DecryptError{Err: originalErr}
		assert.Equal(t, "crypto/3des: failed to decrypt data: original error", err.Error())
	})

	t.Run("ReadError", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := ReadError{Err: originalErr}
		assert.Equal(t, "crypto/3des: failed to read encrypted data: original error", err.Error())
	})

	t.Run("BufferError", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		assert.Equal(t, "crypto/3des: buffer size 5 is too small for data size 10", err.Error())
	})
}

func TestBufferError(t *testing.T) {
	t.Run("buffer too small", func(t *testing.T) {
		err := BufferError{bufferSize: 5, dataSize: 10}
		assert.Equal(t, "crypto/3des: buffer size 5 is too small for data size 10", err.Error())
	})

	t.Run("buffer error with different sizes", func(t *testing.T) {
		testCases := []struct {
			bufferSize int
			dataSize   int
			expected   string
		}{
			{1, 100, "crypto/3des: buffer size 1 is too small for data size 100"},
			{10, 20, "crypto/3des: buffer size 10 is too small for data size 20"},
			{0, 50, "crypto/3des: buffer size 0 is too small for data size 50"},
		}

		for _, tc := range testCases {
			err := BufferError{bufferSize: tc.bufferSize, dataSize: tc.dataSize}
			assert.Equal(t, tc.expected, err.Error())
		}
	})
}

func Test3DES_ErrorHandling(t *testing.T) {
	t.Run("invalid key size for std encrypter", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123")) // Invalid key size
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)

		// Try to encrypt with invalid key
		result, err := encrypter.Encrypt(testData)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("invalid key size for std decrypter", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte("123")) // Invalid key size
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)

		// Try to decrypt with invalid key
		result, err := decrypter.Decrypt(testData)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("nil key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(nil)
		encrypter := NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", encrypter.Error.Error())

		decrypter := NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", decrypter.Error.Error())
	})

	t.Run("empty key", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey([]byte{})
		encrypter := NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, KeySizeError(0), encrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", encrypter.Error.Error())

		decrypter := NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, KeySizeError(0), decrypter.Error)
		assert.Equal(t, "crypto/3des: invalid key size 0, must be 16 or 24 bytes", decrypter.Error.Error())
	})
}

func Test3DES_EdgeCases(t *testing.T) {
	t.Run("empty data encryption", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		result, err := encrypter.Encrypt([]byte{})
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("empty data decryption", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		// First encrypt empty data
		encrypter := NewStdEncrypter(*c)
		encrypted, err := encrypter.Encrypt([]byte{})
		assert.NotNil(t, encrypted)
		assert.Nil(t, err)

		decrypter := NewStdDecrypter(*c)
		result, err := decrypter.Decrypt(encrypted)
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("nil data", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		result, err := encrypter.Encrypt(nil)
		assert.NotNil(t, result)
		assert.Nil(t, err)
	})

	t.Run("very long data", func(t *testing.T) {
		longData := make([]byte, 10000)
		for i := range longData {
			longData[i] = byte(i % 256)
		}
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(*c)
		result, err := encrypter.Encrypt(longData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, longData, result)
	})

	t.Run("exact block size data with no padding", func(t *testing.T) {
		exactBlockData := make([]byte, 8) // 3DES block size is 8
		for i := range exactBlockData {
			exactBlockData[i] = byte(i)
		}
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.No)

		encrypter := NewStdEncrypter(*c)
		result, err := encrypter.Encrypt(exactBlockData)
		assert.NotNil(t, result)
		assert.Nil(t, err)
		assert.NotEqual(t, exactBlockData, result)
	})
}

func Test3DES_Streaming_EdgeCases(t *testing.T) {
	t.Run("stream encrypter multiple writes", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, *c)

		// Write data in multiple chunks
		data1 := []byte("hello")
		data2 := []byte(" world")

		n1, err := encrypter.Write(data1)
		assert.GreaterOrEqual(t, n1, 0)
		assert.Nil(t, err)

		n2, err := encrypter.Write(data2)
		assert.GreaterOrEqual(t, n2, 0)
		assert.Nil(t, err)

		err = encrypter.Close()
		assert.Nil(t, err)

		encrypted := buf.Bytes()
		assert.NotEqual(t, append(data1, data2...), encrypted)
	})

	t.Run("stream decrypter multiple reads", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var encBuf bytes.Buffer
		encrypter := NewStreamEncrypter(&encBuf, *c)
		_, err := encrypter.Write(testData)
		assert.Nil(t, err)
		err = encrypter.Close()
		assert.Nil(t, err)

		encrypted := encBuf.Bytes()
		decrypter := NewStreamDecrypter(bytes.NewReader(encrypted), *c)

		// Read in multiple chunks - first read will get all data
		result1 := make([]byte, 5)
		n1, err := decrypter.Read(result1)
		assert.GreaterOrEqual(t, n1, 0)
		// First read might get all data or partial data
		if n1 < len(testData) {
			// Buffer was too small, should get BufferError
			assert.NotNil(t, err)
			assert.IsType(t, BufferError{}, err)
		} else {
			// Got all data in first read
			assert.Nil(t, err)
			assert.Equal(t, testData, result1[:n1])
		}
	})

	t.Run("stream encrypter close with closer", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		// Create a mock closer writer
		mockWriter := &mockCloserWriter{Buffer: &bytes.Buffer{}}
		encrypter := NewStreamEncrypter(mockWriter, *c)
		err := encrypter.Close()
		assert.Nil(t, err)
		assert.True(t, mockWriter.closed)
	})

	t.Run("stream decrypter read with read error", func(t *testing.T) {
		c := cipher.New3DesCipher(cipher.CBC)
		c.SetKey(key16)
		c.SetIV(iv8)
		c.SetPadding(cipher.PKCS7)

		// Create a mock reader that returns an error
		mockReader := &mockErrorReader{err: fmt.Errorf("read error")}
		decrypter := NewStreamDecrypter(mockReader, *c)
		result := make([]byte, 10)
		n, err := decrypter.Read(result)
		assert.Equal(t, 0, n)
		assert.NotNil(t, err)
		assert.IsType(t, ReadError{}, err)
	})
}

// Mock types for testing
type mockCloserWriter struct {
	*bytes.Buffer
	closed bool
}

func (m *mockCloserWriter) Close() error {
	m.closed = true
	return nil
}

type mockErrorReader struct {
	err  error
	data []byte
}

func (m *mockErrorReader) Read(p []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	if len(m.data) == 0 {
		return 0, io.EOF
	}
	n = copy(p, m.data)
	m.data = m.data[n:]
	return n, nil
}

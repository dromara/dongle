package tea

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestKeySizeError(t *testing.T) {
	t.Run("KeySizeError message", func(t *testing.T) {
		err := KeySizeError(8)
		assert.Contains(t, err.Error(), "invalid key size 8")
		assert.Contains(t, err.Error(), "must be exactly 16 bytes")
	})
}

func TestEncryptError(t *testing.T) {
	t.Run("EncryptError message", func(t *testing.T) {
		originalErr := errors.New("cipher creation failed")
		err := EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to encrypt data")
		assert.Contains(t, err.Error(), "cipher creation failed")
	})
}

func TestDecryptError(t *testing.T) {
	t.Run("DecryptError message", func(t *testing.T) {
		originalErr := errors.New("cipher creation failed")
		err := DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to decrypt data")
		assert.Contains(t, err.Error(), "cipher creation failed")
	})
}

func TestWriteError(t *testing.T) {
	t.Run("WriteError message", func(t *testing.T) {
		originalErr := errors.New("write failed")
		err := WriteError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to write encrypted data")
		assert.Contains(t, err.Error(), "write failed")
	})
}

func TestReadError(t *testing.T) {
	t.Run("ReadError message", func(t *testing.T) {
		originalErr := errors.New("read failed")
		err := ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to read encrypted data")
		assert.Contains(t, err.Error(), "read failed")
	})
}

func TestInvalidDataSizeError(t *testing.T) {
	t.Run("InvalidDataSizeError message", func(t *testing.T) {
		err := InvalidDataSizeError{Size: 7}
		assert.Contains(t, err.Error(), "invalid data size 7")
		assert.Contains(t, err.Error(), "must be a multiple of 8 bytes")
	})
}

func TestNewStdEncrypter_ErrorPaths(t *testing.T) {
	t.Run("KeySizeError in StdEncrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key123456"),
			make([]byte, 32),
		}

		for _, key := range invalidKeys {
			c := cipher.NewTeaCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV([]byte("12345678"))
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
			assert.IsType(t, KeySizeError(0), encrypter.Error)
		}
	})
}

func TestNewStdDecrypter_ErrorPaths(t *testing.T) {
	t.Run("KeySizeError in StdDecrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key123456"),
			make([]byte, 32),
		}

		for _, key := range invalidKeys {
			c := cipher.NewTeaCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV([]byte("12345678"))
			c.SetPadding(cipher.PKCS7)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
		}
	})
}

func TestNewStreamEncrypter_ErrorPaths(t *testing.T) {
	t.Run("KeySizeError in StreamEncrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key123456"),
			make([]byte, 32),
		}

		for _, key := range invalidKeys {
			c := cipher.NewTeaCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV([]byte("12345678"))
			c.SetPadding(cipher.PKCS7)

			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			assert.NotNil(t, encrypter)
			// StreamEncrypter returns interface, check error in Write
			_, err := encrypter.Write([]byte("test"))
			assert.Error(t, err)
			assert.IsType(t, KeySizeError(0), err)
		}
	})
}

func TestNewStreamDecrypter_ErrorPaths(t *testing.T) {
	t.Run("KeySizeError in StreamDecrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key123456"),
			make([]byte, 32),
		}

		for _, key := range invalidKeys {
			c := cipher.NewTeaCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV([]byte("12345678"))
			c.SetPadding(cipher.PKCS7)

			reader := bytes.NewReader([]byte("test"))
			decrypter := NewStreamDecrypter(reader, c)
			assert.NotNil(t, decrypter)
			// StreamDecrypter returns interface, check error in Read
			_, err := decrypter.Read(make([]byte, 10))
			assert.Error(t, err)
			assert.IsType(t, KeySizeError(0), err)
		}
	})
}

func TestStdEncrypter_Encrypt_ErrorPaths(t *testing.T) {
	t.Run("encrypt with existing error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		_, err := encrypter.Encrypt([]byte("hello"))
		assert.Error(t, err)
		// The error might be wrapped in EncryptError
		assert.True(t, err != nil)
	})

	t.Run("encrypt with empty input", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		dst, err := encrypter.Encrypt([]byte{})
		assert.NoError(t, err)
		assert.Empty(t, dst)
	})

	t.Run("encrypt with cipher creation error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Manually set an invalid key to cause cipher creation to fail
		encrypter.cipher.Key = []byte("invalid")

		_, err := encrypter.Encrypt([]byte("hello"))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestStdDecrypter_Decrypt_ErrorPaths(t *testing.T) {
	t.Run("decrypt with existing error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		_, err := decrypter.Decrypt([]byte("hello"))
		assert.Error(t, err)
		// The error might be wrapped in DecryptError
		assert.True(t, err != nil)
	})

	t.Run("decrypt with empty input", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		dst, err := decrypter.Decrypt([]byte{})
		assert.NoError(t, err)
		assert.Empty(t, dst)
	})

	t.Run("decrypt with cipher creation error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Manually set an invalid key to cause cipher creation to fail
		decrypter.cipher.Key = []byte("invalid")

		_, err := decrypter.Decrypt([]byte("hello"))
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestStreamEncrypter_Write_ErrorPaths(t *testing.T) {
	t.Run("write with existing error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write([]byte("hello"))
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("write with underlying writer error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock.ErrorWriteCloser to simulate write error
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encrypter := NewStreamEncrypter(errorWriter, c)

		_, err := encrypter.Write([]byte("hello"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write error")
	})

	t.Run("write with empty input", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write with nil block fallback", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Manually set block to nil to test the fallback path
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			streamEncrypter.block = nil
		}

		_, err := encrypter.Write([]byte("hello"))
		// This should trigger the block creation fallback path
		assert.NoError(t, err) // Should succeed with valid key
	})

}

func TestStreamEncrypter_Close_ErrorPaths(t *testing.T) {
	t.Run("close with existing error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("close with underlying writer close error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock.CloseErrorWriteCloser to simulate close error
		errorWriter := mock.NewCloseErrorWriteCloser(&bytes.Buffer{}, errors.New("close error"))
		encrypter := NewStreamEncrypter(errorWriter, c)

		err := encrypter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "close error")
	})
}

func TestStreamDecrypter_Read_ErrorPaths(t *testing.T) {
	t.Run("read with existing error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test"))
		decrypter := NewStreamDecrypter(reader, c)
		_, err := decrypter.Read(make([]byte, 10))
		assert.Error(t, err)
		assert.IsType(t, KeySizeError(0), err)
	})

	t.Run("read with underlying reader error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock.ErrorFile to simulate read error
		errorReader := mock.NewErrorFile(errors.New("read error"))
		decrypter := NewStreamDecrypter(errorReader, c)

		_, err := decrypter.Read(make([]byte, 10))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read error")
	})

	t.Run("read with EOF", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Empty reader
		reader := bytes.NewReader([]byte{})
		decrypter := NewStreamDecrypter(reader, c)

		_, err := decrypter.Read(make([]byte, 10))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "EOF")
	})

	t.Run("read with empty data returns EOF", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Empty reader - this should trigger the len(encryptedData) == 0 path
		reader := bytes.NewReader([]byte{})
		decrypter := NewStreamDecrypter(reader, c)

		_, err := decrypter.Read(make([]byte, 10))
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with nil block fallback", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Create a decrypter and manually set block to nil to test fallback
		reader := bytes.NewReader([]byte("test"))
		decrypter := NewStreamDecrypter(reader, c)

		// Manually set block to nil to test the fallback path
		if streamDecrypter, ok := decrypter.(*StreamDecrypter); ok {
			streamDecrypter.block = nil
		}

		_, err := decrypter.Read(make([]byte, 10))
		// This should trigger the block creation fallback path
		assert.Error(t, err) // Will likely fail due to invalid data, but covers the path
	})

	t.Run("read with successful decryption", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write([]byte("hello"))
		assert.NoError(t, err)
		encrypter.Close()

		// Now decrypt it
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)

		// Read the decrypted data
		decrypted := make([]byte, 10)
		n, err := decrypter.Read(decrypted)
		assert.NoError(t, err)
		assert.Greater(t, n, 0)
		assert.Contains(t, string(decrypted[:n]), "hello")
	})

	t.Run("read with multiple reads", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// First encrypt some data
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write([]byte("hello world"))
		assert.NoError(t, err)
		encrypter.Close()

		// Now decrypt it with multiple reads
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)

		// First read
		decrypted1 := make([]byte, 5)
		n1, err := decrypter.Read(decrypted1)
		assert.NoError(t, err)
		assert.Greater(t, n1, 0)

		// Second read
		decrypted2 := make([]byte, 10)
		n2, err := decrypter.Read(decrypted2)
		assert.NoError(t, err)
		assert.Greater(t, n2, 0)

		// Third read should return EOF
		decrypted3 := make([]byte, 10)
		n3, err := decrypter.Read(decrypted3)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n3)
	})
}

func TestUnsupportedBlockModeError(t *testing.T) {
	t.Run("unsupported mode error", func(t *testing.T) {
		err := UnsupportedBlockModeError{Mode: "GCM"}
		expected := "crypto/tea: unsupported block mode 'GCM', tea only supports CBC, CTR, ECB, CFB, and OFB modes"
		assert.Equal(t, expected, err.Error())
	})
}

func TestNewStdEncrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StdEncrypter", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "unsupported block mode 'GCM'")
	})
}

func TestNewStdDecrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StdDecrypter", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "unsupported block mode 'GCM'")
	})
}

func TestNewStreamEncrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewTeaCipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, streamEncrypter.Error)
		assert.Contains(t, streamEncrypter.Error.Error(), "unsupported block mode 'GCM'")
	})
}

func TestNewStreamDecrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StreamDecrypter", func(t *testing.T) {
		reader := bytes.NewReader([]byte("test data"))
		c := cipher.NewTeaCipher(cipher.GCM)
		c.SetKey([]byte("1234567890123456"))
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, UnsupportedBlockModeError{}, streamDecrypter.Error)
		assert.Contains(t, streamDecrypter.Error.Error(), "unsupported block mode 'GCM'")
	})
}

func TestStreamEncrypter_WriteWithCipherEncryptError(t *testing.T) {
	t.Run("write with cipher encrypt error", func(t *testing.T) {
		c := cipher.NewTeaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Force the cipher to have an invalid IV to cause encrypt error
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			streamEncrypter.cipher.IV = []byte("invalid") // Invalid IV length
		}

		_, err := encrypter.Write([]byte("hello"))
		assert.Error(t, err)
		assert.IsType(t, EncryptError{}, err)
	})
}

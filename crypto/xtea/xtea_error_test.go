package xtea

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for error testing
var (
	key16Error    = []byte("1234567890123456") // XTEA-128 key
	iv8Error      = []byte("12345678")         // 8-byte IV
	testDataError = []byte("hello world")
)

func TestKeySizeError(t *testing.T) {
	t.Run("invalid key size", func(t *testing.T) {
		err := KeySizeError(8)
		assert.Equal(t, "crypto/xtea: invalid key size 8, must be 16 bytes", err.Error())
	})

	t.Run("valid key size", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error) // Should not have KeySizeError for valid key
	})

	t.Run("invalid key sizes", func(t *testing.T) {
		invalidSizes := []int{0, 1, 8, 15, 17, 32, 64}
		for _, size := range invalidSizes {
			err := KeySizeError(size)
			assert.Contains(t, err.Error(), "must be 16 bytes")
		}
	})
}

func TestEncryptError(t *testing.T) {
	t.Run("encrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := EncryptError{Err: originalErr}
		assert.Equal(t, "crypto/xtea: failed to encrypt data: original error", err.Error())
	})

	t.Run("with nil error", func(t *testing.T) {
		err := EncryptError{Err: nil}
		expected := "crypto/xtea: failed to encrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})
}

func TestDecryptError(t *testing.T) {
	t.Run("decrypt error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := DecryptError{Err: originalErr}
		assert.Equal(t, "crypto/xtea: failed to decrypt data: original error", err.Error())
	})

	t.Run("with nil error", func(t *testing.T) {
		err := DecryptError{Err: nil}
		expected := "crypto/xtea: failed to decrypt data: <nil>"
		assert.Equal(t, expected, err.Error())
	})
}

func TestReadError(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := ReadError{Err: originalErr}
		assert.Equal(t, "crypto/xtea: failed to read encrypted data: original error", err.Error())
	})

	t.Run("with nil error", func(t *testing.T) {
		err := ReadError{Err: nil}
		expected := "crypto/xtea: failed to read encrypted data: <nil>"
		assert.Equal(t, expected, err.Error())
	})
}

func TestBufferError(t *testing.T) {
	t.Run("buffer error", func(t *testing.T) {
		err := BufferError{bufferSize: 10, dataSize: 20}
		assert.Equal(t, "crypto/xtea: buffer size 10 is too small for data size 20", err.Error())
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
			c := cipher.NewXteaCipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv8Error)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
			assert.IsType(t, KeySizeError(0), encrypter.Error)
		}
	})

	t.Run("valid configuration", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.Nil(t, encrypter.Error)
	})
}

func TestNewStdDecrypter_ErrorPaths(t *testing.T) {
	t.Run("KeySizeError in StdDecrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
		}

		for _, key := range invalidKeys {
			c := cipher.NewXteaCipher(cipher.CBC)
			c.SetKey(key)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
		}
	})

	t.Run("valid configuration", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.Nil(t, decrypter.Error)
	})
}

func TestStdEncrypter_Encrypt_ErrorPaths(t *testing.T) {
	t.Run("encrypt with existing error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key size
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)

		// Try to encrypt with existing error - it will still try to encrypt
		result, err := encrypter.Encrypt(testDataError)
		// The encryption will fail because the key is invalid
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encrypt with invalid key causing xtea.NewCipher error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Manually set an invalid key to cause xtea.NewCipher to fail
		encrypter.cipher.Key = []byte("invalid")

		result, err := encrypter.Encrypt(testDataError)
		// The encryption will fail because the key is invalid
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("encrypt with xtea.NewCipher error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Set a key that will cause xtea.NewCipher to fail
		encrypter.cipher.Key = nil // This should cause xtea.NewCipher to fail

		result, err := encrypter.Encrypt(testDataError)
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})
}

func TestStdDecrypter_Decrypt_ErrorPaths(t *testing.T) {
	t.Run("decrypt with existing error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("short")) // Invalid key size
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)

		// Try to decrypt with existing error - it will still try to decrypt
		result, err := decrypter.Decrypt(testDataError)
		// The decryption will fail because the key is invalid
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("decrypt with invalid key causing xtea.NewCipher error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Manually set an invalid key to cause xtea.NewCipher to fail
		decrypter.cipher.Key = []byte("invalid")

		result, err := decrypter.Decrypt(testDataError)
		// The decryption will fail because the key is invalid
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("decrypt with xtea.NewCipher error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Set a key that will cause xtea.NewCipher to fail
		decrypter.cipher.Key = nil // This should cause xtea.NewCipher to fail

		result, err := decrypter.Decrypt(testDataError)
		assert.Empty(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestNewStreamEncrypter_ErrorPaths(t *testing.T) {
	t.Run("KeySizeError in StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("valid configuration", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)
	})
}

func TestNewStreamDecrypter_ErrorPaths(t *testing.T) {
	t.Run("KeySizeError in StreamDecrypter", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})

	t.Run("valid configuration", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)
	})
}

func TestStreamEncrypter_WriteWithError(t *testing.T) {
	t.Run("write with existing error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Set an error on the encrypter
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			streamEncrypter.Error = errors.New("existing error")
		}

		_, err := encrypter.Write([]byte("hello"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "existing error")
	})
}

func TestStreamEncrypter_WriteEmptyData(t *testing.T) {
	t.Run("write empty data", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		n, err := encrypter.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_WriteWithWriteError(t *testing.T) {
	t.Run("write with underlying writer error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
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
}

func TestStreamEncrypter_CloseWithError(t *testing.T) {
	t.Run("close with existing error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Set an error on the encrypter
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			streamEncrypter.Error = errors.New("existing error")
		}

		err := encrypter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "existing error")
	})
}

func TestStreamEncrypter_CloseWithWriterError(t *testing.T) {
	t.Run("close with underlying writer close error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock.CloseErrorWriteCloser to simulate close error
		var buf bytes.Buffer
		errorWriter := mock.NewCloseErrorWriteCloser(&buf, errors.New("close error"))
		encrypter := NewStreamEncrypter(errorWriter, c)

		err := encrypter.Close()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "close error")
	})
}

func TestStreamEncrypter_CloseWithNonCloserWriter(t *testing.T) {
	t.Run("close with writer that doesn't implement Closer", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use bytes.Buffer which doesn't implement io.Closer
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		err := encrypter.Close()
		assert.Nil(t, err) // Should return nil when writer doesn't implement Closer
	})
}

func TestStreamDecrypter_ReadWithError(t *testing.T) {
	t.Run("read with existing error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test data"))
		decrypter := NewStreamDecrypter(reader, c)

		// Set an error on the decrypter
		if streamDecrypter, ok := decrypter.(*StreamDecrypter); ok {
			streamDecrypter.Error = errors.New("existing error")
		}

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "existing error")
	})
}

func TestStreamDecrypter_ReadWithReaderError(t *testing.T) {
	t.Run("read with underlying reader error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Use mock.ErrorFile to simulate read error
		errorReader := mock.NewErrorFile(errors.New("read error"))
		decrypter := NewStreamDecrypter(errorReader, c)

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read error")
	})
}

func TestStreamDecrypter_ReadWithDecryptError(t *testing.T) {
	t.Run("read with decrypt error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Create some invalid encrypted data that will cause decrypt to fail
		reader := bytes.NewReader([]byte("invalid encrypted data"))
		decrypter := NewStreamDecrypter(reader, c)

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestStreamDecrypter_ReadWithNilBlock(t *testing.T) {
	t.Run("read with nil block", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test data"))
		decrypter := NewStreamDecrypter(reader, c)

		// Force the block to be nil
		if streamDecrypter, ok := decrypter.(*StreamDecrypter); ok {
			streamDecrypter.block = nil
		}

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestStreamDecrypter_ReadWithNilBlockRecreation(t *testing.T) {
	t.Run("read with nil block recreation", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test data"))
		decrypter := NewStreamDecrypter(reader, c)

		// Force the block to be nil but with valid key
		if streamDecrypter, ok := decrypter.(*StreamDecrypter); ok {
			streamDecrypter.block = nil
		}

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Error(t, err) // This will fail because the data is not properly encrypted
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestStreamEncrypter_WriteWithNilBlockAndValidKey(t *testing.T) {
	t.Run("write with nil block but valid key", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Force the block to be nil but keep valid key
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			streamEncrypter.block = nil
		}

		_, err := encrypter.Write([]byte("hello"))
		assert.Nil(t, err) // Should succeed as it will recreate the block
	})
}

func TestStreamDecrypter_ReadWithNilBlockAndValidKey(t *testing.T) {
	t.Run("read with nil block but valid key", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Create properly encrypted data first
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write([]byte("hello"))
		encrypter.Close()

		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)

		// Force the block to be nil but keep valid key
		if streamDecrypter, ok := decrypter.(*StreamDecrypter); ok {
			streamDecrypter.block = nil
		}

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Nil(t, err) // Should succeed as it will recreate the block
	})
}

func TestStreamEncrypter_WriteWithBufferAccumulation(t *testing.T) {
	t.Run("write with buffer accumulation", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Write small chunks to test buffer accumulation
		_, err1 := encrypter.Write([]byte("h"))
		assert.Nil(t, err1)

		_, err2 := encrypter.Write([]byte("ello"))
		assert.Nil(t, err2)

		err3 := encrypter.Close()
		assert.Nil(t, err3)
	})
}

func TestStreamDecrypter_ReadWithPartialData(t *testing.T) {
	t.Run("read with partial data", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Create properly encrypted data first
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		encrypter.Write([]byte("hello"))
		encrypter.Close()

		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)

		// Read in small chunks
		buffer1 := make([]byte, 2)
		n1, err1 := decrypter.Read(buffer1)
		assert.Nil(t, err1)
		assert.Equal(t, 2, n1)

		buffer2 := make([]byte, 10)
		n2, err2 := decrypter.Read(buffer2)
		assert.Nil(t, err2)
		assert.Equal(t, 3, n2) // Remaining 3 bytes
	})
}

func TestStreamDecrypter_ReadWithEOF(t *testing.T) {
	t.Run("read with EOF", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey([]byte("1234567890123456"))
		c.SetIV([]byte("12345678"))
		c.SetPadding(cipher.PKCS7)

		// Create empty reader
		reader := bytes.NewReader([]byte{})
		decrypter := NewStreamDecrypter(reader, c)

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "EOF")
	})
}

func TestUnsupportedModeError(t *testing.T) {
	t.Run("unsupported mode error", func(t *testing.T) {
		err := UnsupportedModeError{Mode: "GCM"}
		expected := "crypto/xtea: unsupported cipher mode 'GCM', xtea only supports CBC, CTR, ECB, CFB, and OFB modes"
		assert.Equal(t, expected, err.Error())
	})
}

func TestNewStdEncrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StdEncrypter", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter)
		assert.NotNil(t, encrypter.Error)
		assert.IsType(t, UnsupportedModeError{}, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "unsupported cipher mode 'GCM'")
	})
}

func TestNewStdDecrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StdDecrypter", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter)
		assert.NotNil(t, decrypter.Error)
		assert.IsType(t, UnsupportedModeError{}, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "unsupported cipher mode 'GCM'")
	})
}

func TestNewStreamEncrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewXteaCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, UnsupportedModeError{}, streamEncrypter.Error)
		assert.Contains(t, streamEncrypter.Error.Error(), "unsupported cipher mode 'GCM'")
	})
}

func TestNewStreamDecrypter_GCMError(t *testing.T) {
	t.Run("GCM mode error in StreamDecrypter", func(t *testing.T) {
		reader := bytes.NewReader([]byte("test data"))
		c := cipher.NewXteaCipher(cipher.GCM)
		c.SetKey(key16Error)
		c.SetNonce([]byte("1234567890123456")) // 16-byte nonce for GCM

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, UnsupportedModeError{}, streamDecrypter.Error)
		assert.Contains(t, streamDecrypter.Error.Error(), "unsupported cipher mode 'GCM'")
	})
}

func TestStreamEncrypter_WriteWithCipherError(t *testing.T) {
	t.Run("write with cipher encrypt error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Force the cipher to have an invalid key to cause encrypt error
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			streamEncrypter.cipher.Key = []byte("invalid")
			streamEncrypter.block = nil // Ensure block is nil so it tries to recreate
		}

		// This will panic because block is nil and cipher.Encrypt will be called with nil block
		assert.Panics(t, func() {
			encrypter.Write([]byte("hello"))
		})
	})
}

func TestStreamDecrypter_ReadWithNilBlockAndInvalidKey(t *testing.T) {
	t.Run("read with nil block and invalid key", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		reader := bytes.NewReader([]byte("test data"))
		decrypter := NewStreamDecrypter(reader, c)

		// Force the block to be nil and key to be invalid
		if streamDecrypter, ok := decrypter.(*StreamDecrypter); ok {
			streamDecrypter.block = nil
			streamDecrypter.cipher.Key = []byte("invalid")
		}

		buffer := make([]byte, 10)
		_, err := decrypter.Read(buffer)
		assert.Error(t, err)
		assert.IsType(t, DecryptError{}, err)
	})
}

func TestStreamEncrypter_WriteWithNilBlockRecreation(t *testing.T) {
	t.Run("write with nil block recreation", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)

		// Force the block to be nil but keep valid key
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			streamEncrypter.block = nil
		}

		_, err := encrypter.Write([]byte("hello"))
		assert.Nil(t, err) // Should succeed as it will recreate the block

		// Verify that the block was recreated
		if streamEncrypter, ok := encrypter.(*StreamEncrypter); ok {
			assert.NotNil(t, streamEncrypter.block)
		}
	})
}

func TestStreamEncrypter_WriteWithCipherEncryptError(t *testing.T) {
	t.Run("write with cipher encrypt error", func(t *testing.T) {
		c := cipher.NewXteaCipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv8Error)
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

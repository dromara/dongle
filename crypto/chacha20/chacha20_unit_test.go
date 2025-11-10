package chacha20

import (
	"bytes"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data constants
var (
	key32ChaCha20    = []byte("dongle1234567890abcdef123456789x") // 32 bytes
	nonce12ChaCha20  = []byte("123456789012")                     // 12 bytes
	testdataChaCha20 = []byte("hello world from chacha20")        // Test data
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid key and nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce12ChaCha20)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce([]byte("short")) // 5 bytes

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid key and nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce12ChaCha20)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce([]byte("short")) // 5 bytes

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("valid encryption", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt(testdataChaCha20)
		assert.Nil(t, err)
		assert.Equal(t, len(testdataChaCha20), len(result))
		assert.NotEqual(t, testdataChaCha20, result) // Should be different
	})

	t.Run("empty data", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("with existing error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		// Set an error
		encrypter.Error = assert.AnError

		// Try to encrypt
		_, err := encrypter.Encrypt(testdataChaCha20)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("valid decryption", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testdataChaCha20)
		assert.Nil(t, err)

		// Reset cipher for decryption (stream ciphers need fresh state)
		c2 := cipher.NewChaCha20Cipher()
		c2.SetKey(key32ChaCha20)
		c2.SetNonce(nonce12ChaCha20)

		// Then decrypt
		decrypter := NewStdDecrypter(c2)
		assert.Nil(t, decrypter.Error)
		result, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, testdataChaCha20, result)
	})

	t.Run("empty data", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		result, err := decrypter.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Nil(t, result)
	})

	t.Run("with existing error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		// Set an error
		decrypter.Error = assert.AnError

		// Try to decrypt
		_, err := decrypter.Decrypt(testdataChaCha20)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid key and nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.NotNil(t, streamEncrypter.(*StreamEncrypter).Error)
		assert.Contains(t, streamEncrypter.(*StreamEncrypter).Error.Error(), "invalid key size 5")
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce([]byte("short")) // 5 bytes

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.NotNil(t, streamEncrypter.(*StreamEncrypter).Error)
		assert.Contains(t, streamEncrypter.(*StreamEncrypter).Error.Error(), "invalid nonce size 5")
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("write data", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		n, err := streamEncrypter.Write(testdataChaCha20)
		assert.Nil(t, err)
		assert.Equal(t, len(testdataChaCha20), n)
	})

	t.Run("write empty data", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		n, err := streamEncrypter.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write with existing error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Set an error
		streamEncrypter.(*StreamEncrypter).Error = assert.AnError

		// Try to write
		_, err := streamEncrypter.Write(testdataChaCha20)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("write with write error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		// Create a mock writer that returns error
		errorWriter := mock.NewErrorReadWriteCloser(assert.AnError)
		streamEncrypter := NewStreamEncrypter(errorWriter, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Try to write
		_, err := streamEncrypter.Write(testdataChaCha20)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to write encrypted data")
	})

	t.Run("write with nil stream", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)

		// Set stream to nil to test fallback
		streamEncrypter.(*StreamEncrypter).stream = nil

		n, err := streamEncrypter.Write(testdataChaCha20)
		assert.Nil(t, err)
		assert.Equal(t, len(testdataChaCha20), n)
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("close with closer", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		mockCloser := mock.NewWriteCloser(&bytes.Buffer{})
		streamEncrypter := NewStreamEncrypter(mockCloser, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		err := streamEncrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close without closer", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		err := streamEncrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close with existing error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)

		// Set an existing error
		streamEncrypter.(*StreamEncrypter).Error = assert.AnError

		err := streamEncrypter.Close()
		assert.Equal(t, assert.AnError, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid key and nonce", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		file := mock.NewFile(testdataChaCha20, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)
	})

	t.Run("invalid key size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce12ChaCha20)

		file := mock.NewFile(testdataChaCha20, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.NotNil(t, streamDecrypter.(*StreamDecrypter).Error)
		assert.Contains(t, streamDecrypter.(*StreamDecrypter).Error.Error(), "invalid key size 5")
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce([]byte("short")) // 5 bytes

		file := mock.NewFile(testdataChaCha20, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.NotNil(t, streamDecrypter.(*StreamDecrypter).Error)
		assert.Contains(t, streamDecrypter.(*StreamDecrypter).Error.Error(), "invalid nonce size 5")
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("read decrypted data", func(t *testing.T) {
		c1 := cipher.NewChaCha20Cipher()
		c1.SetKey(key32ChaCha20)
		c1.SetNonce(nonce12ChaCha20)

		// First encrypt some data
		encrypter := NewStdEncrypter(c1)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testdataChaCha20)
		assert.Nil(t, err)

		// Then create stream decrypter with fresh cipher
		c2 := cipher.NewChaCha20Cipher()
		c2.SetKey(key32ChaCha20)
		c2.SetNonce(nonce12ChaCha20)

		file := mock.NewFile(encrypted, "encrypted.dat")
		streamDecrypter := NewStreamDecrypter(file, c2)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Read decrypted data
		buffer := make([]byte, len(testdataChaCha20))
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, len(testdataChaCha20), n)
		assert.Equal(t, testdataChaCha20, buffer)
	})

	t.Run("read empty buffer", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		file := mock.NewFile(testdataChaCha20, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		buffer := make([]byte, 0)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with existing error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		file := mock.NewFile(testdataChaCha20, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Set an error
		streamDecrypter.(*StreamDecrypter).Error = assert.AnError

		buffer := make([]byte, len(testdataChaCha20))
		_, err := streamDecrypter.Read(buffer)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("read with read error", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		streamDecrypter := NewStreamDecrypter(errorReader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		buffer := make([]byte, len(testdataChaCha20))
		_, err := streamDecrypter.Read(buffer)
		assert.Equal(t, assert.AnError, err) // Direct error from reader, no wrapping
	})

	t.Run("read with eof", func(t *testing.T) {
		c := cipher.NewChaCha20Cipher()
		c.SetKey(key32ChaCha20)
		c.SetNonce(nonce12ChaCha20)

		eofReader := mock.NewFile([]byte{}, "eof.txt")
		streamDecrypter := NewStreamDecrypter(eofReader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		buffer := make([]byte, len(testdataChaCha20))
		_, err := streamDecrypter.Read(buffer)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("multiple reads until eof", func(t *testing.T) {
		c1 := cipher.NewChaCha20Cipher()
		c1.SetKey(key32ChaCha20)
		c1.SetNonce(nonce12ChaCha20)

		// First encrypt some data
		encrypter := NewStdEncrypter(c1)
		encrypted, err := encrypter.Encrypt(testdataChaCha20)
		assert.Nil(t, err)

		// Create decrypter with fresh cipher
		c2 := cipher.NewChaCha20Cipher()
		c2.SetKey(key32ChaCha20)
		c2.SetNonce(nonce12ChaCha20)

		file := mock.NewFile(encrypted, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c2)

		// Read once to get all data
		buffer := make([]byte, len(testdataChaCha20))
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, len(testdataChaCha20), n)

		// Read again should return EOF
		n, err = streamDecrypter.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with nil stream", func(t *testing.T) {
		c1 := cipher.NewChaCha20Cipher()
		c1.SetKey(key32ChaCha20)
		c1.SetNonce(nonce12ChaCha20)

		// First encrypt some data
		encrypter := NewStdEncrypter(c1)
		encrypted, err := encrypter.Encrypt(testdataChaCha20)
		assert.Nil(t, err)

		// Create decrypter and set stream to nil to test fallback
		c2 := cipher.NewChaCha20Cipher()
		c2.SetKey(key32ChaCha20)
		c2.SetNonce(nonce12ChaCha20)

		file := mock.NewFile(encrypted, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c2)
		streamDecrypter.(*StreamDecrypter).stream = nil

		buffer := make([]byte, len(testdataChaCha20))
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, len(testdataChaCha20), n)
		assert.Equal(t, testdataChaCha20, buffer)
	})
}

func TestErrors(t *testing.T) {
	t.Run("key size error", func(t *testing.T) {
		err := KeySizeError(16)
		assert.Contains(t, err.Error(), "invalid key size 16")
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
	})

	t.Run("invalid nonce size error", func(t *testing.T) {
		err := InvalidNonceSizeError{Size: 8}
		assert.Contains(t, err.Error(), "invalid nonce size 8")
		assert.Contains(t, err.Error(), "must be exactly 12 bytes")
	})

	t.Run("encrypt error", func(t *testing.T) {
		originalErr := assert.AnError
		err := EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})

	t.Run("decrypt error", func(t *testing.T) {
		originalErr := assert.AnError
		err := DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("write error", func(t *testing.T) {
		originalErr := assert.AnError
		err := WriteError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to write encrypted data")
	})

	t.Run("read error", func(t *testing.T) {
		originalErr := assert.AnError
		err := ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to read encrypted data")
	})
}

// TestCipherCreationErrors tests error paths in Encrypt and Decrypt methods
// when chacha20.NewUnauthenticatedCipher fails
func TestCipherCreationErrors(t *testing.T) {
	t.Run("encrypt cipher creation error", func(t *testing.T) {
		// Create an encrypter by bypassing constructor validation
		// to test the error path in Encrypt method
		invalidCipher := &cipher.ChaCha20Cipher{}
		invalidCipher.SetKey(make([]byte, 16)) // Invalid key size (16 instead of 32)
		invalidCipher.SetNonce(nonce12ChaCha20)

		// Create encrypter without using NewStdEncrypter to bypass validation
		encrypter := &StdEncrypter{
			cipher: invalidCipher,
			Error:  nil, // No error initially
		}

		// Try to encrypt - this should trigger the error path when
		// chacha20.NewUnauthenticatedCipher fails due to invalid key size
		_, err := encrypter.Encrypt(testdataChaCha20)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})

	t.Run("decrypt cipher creation error", func(t *testing.T) {
		// Create a decrypter by bypassing constructor validation
		// to test the error path in Decrypt method
		invalidCipher := &cipher.ChaCha20Cipher{}
		invalidCipher.SetKey(make([]byte, 16)) // Invalid key size (16 instead of 32)
		invalidCipher.SetNonce(nonce12ChaCha20)

		// Create decrypter without using NewStdDecrypter to bypass validation
		decrypter := &StdDecrypter{
			cipher: invalidCipher,
			Error:  nil, // No error initially
		}

		// Try to decrypt - this should trigger the error path when
		// chacha20.NewUnauthenticatedCipher fails due to invalid key size
		_, err := decrypter.Decrypt(testdataChaCha20)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

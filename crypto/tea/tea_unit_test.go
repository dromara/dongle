package tea

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
	key16Tea     = []byte("dongle1234567890") // 16 bytes
	testdata8Tea = []byte("12345678")         // 8 bytes (block-aligned)
	testdataTea  = []byte("hello world")      // 11 bytes (not block-aligned)
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size 5")
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size 5")
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("valid_encryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt(testdata8Tea)
		assert.Nil(t, err)
		assert.Equal(t, 8, len(result))
	})

	t.Run("invalid_data_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		_, err := encrypter.Encrypt(testdataTea) // 11 bytes, not block-aligned
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 11")
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		// Set an error
		encrypter.Error = assert.AnError

		// Try to encrypt
		_, err := encrypter.Encrypt(testdata8Tea)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("valid_decryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testdata8Tea)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)
		result, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, testdata8Tea, result)
	})

	t.Run("invalid_data_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		_, err := decrypter.Decrypt(testdataTea) // 11 bytes, not block-aligned
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 11")
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		result, err := decrypter.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		// Set an error
		decrypter.Error = assert.AnError

		// Try to decrypt
		_, err := decrypter.Decrypt(testdata8Tea)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("with_cipher_error", func(t *testing.T) {
		// Create a cipher with invalid rounds to trigger tea.NewCipherWithRounds error
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)
		c.SetRounds(-1) // Invalid rounds

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		// Try to decrypt - this should fail due to invalid rounds
		_, err := decrypter.Decrypt(testdata8Tea)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.NotNil(t, streamEncrypter.(*StreamEncrypter).Error)
		assert.Contains(t, streamEncrypter.(*StreamEncrypter).Error.Error(), "invalid key size 5")
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("write_complete_blocks", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Write 8-byte data (complete block)
		n, err := streamEncrypter.Write(testdata8Tea)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
	})

	t.Run("write_incomplete_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Write 5-byte data (incomplete block)
		_, err := streamEncrypter.Write([]byte("12345"))
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 5")
	})

	t.Run("write_empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Write empty data
		n, err := streamEncrypter.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write_with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Set an error
		streamEncrypter.(*StreamEncrypter).Error = assert.AnError

		// Try to write
		_, err := streamEncrypter.Write(testdata8Tea)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("close_with_closer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// Create a mock closer
		mockCloser := mock.NewWriteCloser(&bytes.Buffer{})
		streamEncrypter := NewStreamEncrypter(mockCloser, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Close
		err := streamEncrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("close_without_closer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Close
		err := streamEncrypter.Close()
		assert.Nil(t, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		file := mock.NewFile(testdata8Tea, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		file := mock.NewFile(testdata8Tea, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.NotNil(t, streamDecrypter.(*StreamDecrypter).Error)
		assert.Contains(t, streamDecrypter.(*StreamDecrypter).Error.Error(), "invalid key size 5")
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("read_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// First encrypt some data
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testdata8Tea)
		assert.Nil(t, err)

		// Then create stream decrypter
		file := mock.NewFile(encrypted, "encrypted.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Read decrypted data
		buffer := make([]byte, 8)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
	})

	t.Run("read_empty_buffer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		file := mock.NewFile(testdata8Tea, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Read with empty buffer
		buffer := make([]byte, 0)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read_with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		file := mock.NewFile(testdata8Tea, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Set an error
		streamDecrypter.(*StreamDecrypter).Error = assert.AnError

		// Try to read
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("read_partial_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// Create a reader that returns partial data
		partialReader := mock.NewFile([]byte("12345"), "partial.txt")
		streamDecrypter := NewStreamDecrypter(partialReader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Try to read
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unexpected EOF")
	})
}

func TestErrors(t *testing.T) {
	t.Run("key_size_error", func(t *testing.T) {
		err := KeySizeError(5)
		assert.Contains(t, err.Error(), "invalid key size 5")
		assert.Contains(t, err.Error(), "must be exactly 16 bytes")
	})

	t.Run("encrypt_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})

	t.Run("decrypt_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("write_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := WriteError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to write encrypted data")
	})

	t.Run("read_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to read encrypted data")
	})

	t.Run("invalid_data_size_error", func(t *testing.T) {
		err := InvalidDataSizeError{Size: 11}
		assert.Contains(t, err.Error(), "invalid data size 11")
		assert.Contains(t, err.Error(), "must be a multiple of 8 bytes")
	})
}

func TestStreamEncrypter_Write_ErrorCases(t *testing.T) {
	t.Run("write_with_write_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// Create a mock writer that returns error
		errorWriter := mock.NewErrorReadWriteCloser(assert.AnError)
		streamEncrypter := NewStreamEncrypter(errorWriter, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Try to write
		_, err := streamEncrypter.Write(testdata8Tea)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to write encrypted data")
	})

	t.Run("write_with_cipher_error", func(t *testing.T) {
		// Create a cipher with invalid rounds to trigger tea.NewCipherWithRounds error
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)
		c.SetRounds(-1) // Invalid rounds

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Try to write - this should fail due to invalid rounds
		_, err := streamEncrypter.Write(testdata8Tea)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})
}

func TestStreamDecrypter_Read_ErrorCases(t *testing.T) {
	t.Run("read_with_read_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// Create a reader that returns error
		errorReader := mock.NewErrorReadWriteCloser(assert.AnError)
		streamDecrypter := NewStreamDecrypter(errorReader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Try to read
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to read encrypted data")
	})

	t.Run("read_with_eof", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// Create a reader that returns EOF
		eofReader := mock.NewFile([]byte{}, "eof.txt")
		streamDecrypter := NewStreamDecrypter(eofReader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Try to read
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read_with_eof_and_zero_bytes", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// Create a reader that returns EOF with 0 bytes read
		eofZeroReader := mock.NewFile([]byte{}, "eof_zero.txt")
		streamDecrypter := NewStreamDecrypter(eofZeroReader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Try to read
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read_with_cipher_error", func(t *testing.T) {
		// Create a cipher with invalid rounds to trigger tea.NewCipherWithRounds error
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)
		c.SetRounds(-1) // Invalid rounds

		file := mock.NewFile(testdata8Tea, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Try to read - this should fail due to invalid rounds
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("read_with_large_buffer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// First encrypt some data
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testdata8Tea)
		assert.Nil(t, err)

		// Then create stream decrypter
		file := mock.NewFile(encrypted, "encrypted.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Read with large buffer (larger than block size)
		buffer := make([]byte, 16)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
	})
}

// Test cases to achieve 100% coverage
func TestCoverageCompleteness(t *testing.T) {
	t.Run("encrypt with nil block and empty data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		encrypter := NewStdEncrypter(c)
		// Set block to nil to test fallback
		encrypter.block = nil

		result, err := encrypter.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("decrypt with nil block and empty data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		decrypter := NewStdDecrypter(c)
		// Set block to nil to test fallback
		decrypter.block = nil

		result, err := decrypter.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("stream encrypter close with buffered data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Manually add data to buffer to simulate incomplete block
		streamEncrypter.(*StreamEncrypter).buffer = []byte("123")

		// Close should return error due to incomplete block
		err := streamEncrypter.Close()
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 3")
	})

	t.Run("stream encrypter close with error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)

		// Set an existing error
		streamEncrypter.(*StreamEncrypter).Error = assert.AnError

		// Close should return the existing error
		err := streamEncrypter.Close()
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream decrypter with nil block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// First encrypt some data normally
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testdata8Tea)
		assert.Nil(t, err)

		// Create decrypter and set block to nil to test fallback
		file := mock.NewFile(encrypted, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)
		streamDecrypter.(*StreamDecrypter).block = nil

		// Read should work using fallback cipher creation
		buffer := make([]byte, 8)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
		assert.Equal(t, testdata8Tea, buffer)
	})

	t.Run("stream encrypter write with nil block fallback", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)

		// Set block to nil to test fallback path
		streamEncrypter.(*StreamEncrypter).block = nil

		// Write should work using fallback cipher creation
		n, err := streamEncrypter.Write(testdata8Tea)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
		assert.NotNil(t, streamEncrypter.(*StreamEncrypter).block)
	})

	t.Run("stream encrypter buffering behavior", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)

		// Add some partial data to buffer first
		streamEncrypter.(*StreamEncrypter).buffer = []byte("1234")

		// Write more data that will combine with buffer to form complete blocks
		n, err := streamEncrypter.Write([]byte("5678ABCD"))
		assert.Nil(t, err)
		assert.Equal(t, 8, n)                                              // Should return length of new data written
		assert.Equal(t, 4, len(streamEncrypter.(*StreamEncrypter).buffer)) // Remaining bytes
	})

	t.Run("stream decrypter multiple reads until EOF", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16Tea)

		// First encrypt some data
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testdata8Tea)
		assert.Nil(t, err)

		// Create decrypter
		file := mock.NewFile(encrypted, "test.dat")
		streamDecrypter := NewStreamDecrypter(file, c)

		// Read once to get all data
		buffer := make([]byte, 8)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)

		// Read again should return EOF
		n, err = streamDecrypter.Read(buffer)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

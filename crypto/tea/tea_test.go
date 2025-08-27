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
	key16_tea     = []byte("dongle1234567890") // 16 bytes
	testData8_tea = []byte("12345678")         // 8 bytes (block-aligned)
	testData_tea  = []byte("hello world")      // 11 bytes (not block-aligned)
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt(testData8_tea)
		assert.Nil(t, err)
		assert.Equal(t, 8, len(result))
	})

	t.Run("invalid_data_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		_, err := encrypter.Encrypt(testData_tea) // 11 bytes, not block-aligned
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 11")
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		// Set an error
		encrypter.Error = assert.AnError

		// Try to encrypt
		_, err := encrypter.Encrypt(testData8_tea)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("with_cipher_error", func(t *testing.T) {
		// Create a cipher with invalid rounds to trigger tea.NewCipherWithRounds error
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)
		c.SetRounds(-1) // Invalid rounds

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)

		// Try to encrypt - this should fail due to invalid rounds
		_, err := encrypter.Encrypt(testData8_tea)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("valid_decryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testData8_tea)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)
		result, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, testData8_tea, result)
	})

	t.Run("invalid_data_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		_, err := decrypter.Decrypt(testData_tea) // 11 bytes, not block-aligned
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 11")
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		result, err := decrypter.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		// Set an error
		decrypter.Error = assert.AnError

		// Try to decrypt
		_, err := decrypter.Decrypt(testData8_tea)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("with_cipher_error", func(t *testing.T) {
		// Create a cipher with invalid rounds to trigger tea.NewCipherWithRounds error
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)
		c.SetRounds(-1) // Invalid rounds

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)

		// Try to decrypt - this should fail due to invalid rounds
		_, err := decrypter.Decrypt(testData8_tea)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Write 8-byte data (complete block)
		n, err := streamEncrypter.Write(testData8_tea)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
	})

	t.Run("write_incomplete_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Set an error
		streamEncrypter.(*StreamEncrypter).Error = assert.AnError

		// Try to write
		_, err := streamEncrypter.Write(testData8_tea)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("close_with_closer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

		reader := bytes.NewReader(testData8_tea)
		streamDecrypter := NewStreamDecrypter(reader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		reader := bytes.NewReader(testData8_tea)
		streamDecrypter := NewStreamDecrypter(reader, c)
		assert.NotNil(t, streamDecrypter.(*StreamDecrypter).Error)
		assert.Contains(t, streamDecrypter.(*StreamDecrypter).Error.Error(), "invalid key size 5")
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("read_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt some data
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testData8_tea)
		assert.Nil(t, err)

		// Then create stream decrypter
		reader := bytes.NewReader(encrypted)
		streamDecrypter := NewStreamDecrypter(reader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Read decrypted data
		buffer := make([]byte, 8)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
	})

	t.Run("read_empty_buffer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		reader := bytes.NewReader(testData8_tea)
		streamDecrypter := NewStreamDecrypter(reader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Read with empty buffer
		buffer := make([]byte, 0)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read_with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		reader := bytes.NewReader(testData8_tea)
		streamDecrypter := NewStreamDecrypter(reader, c)
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
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

		// Create a mock writer that returns error
		errorWriter := mock.NewErrorReadWriteCloser(assert.AnError)
		streamEncrypter := NewStreamEncrypter(errorWriter, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Try to write
		_, err := streamEncrypter.Write(testData8_tea)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to write encrypted data")
	})

	t.Run("write_with_cipher_error", func(t *testing.T) {
		// Create a cipher with invalid rounds to trigger tea.NewCipherWithRounds error
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)
		c.SetRounds(-1) // Invalid rounds

		writer := &bytes.Buffer{}
		streamEncrypter := NewStreamEncrypter(writer, c)
		assert.Nil(t, streamEncrypter.(*StreamEncrypter).Error)

		// Try to write - this should fail due to invalid rounds
		_, err := streamEncrypter.Write(testData8_tea)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt data")
	})
}

func TestStreamDecrypter_Read_ErrorCases(t *testing.T) {
	t.Run("read_with_read_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)

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
		c.SetKey(key16_tea)
		c.SetRounds(-1) // Invalid rounds

		reader := bytes.NewReader(testData8_tea)
		streamDecrypter := NewStreamDecrypter(reader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Try to read - this should fail due to invalid rounds
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("read_with_large_buffer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt some data
		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testData8_tea)
		assert.Nil(t, err)

		// Then create stream decrypter
		reader := bytes.NewReader(encrypted)
		streamDecrypter := NewStreamDecrypter(reader, c)
		assert.Nil(t, streamDecrypter.(*StreamDecrypter).Error)

		// Read with large buffer (larger than block size)
		buffer := make([]byte, 16)
		n, err := streamDecrypter.Read(buffer)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)
	})
}

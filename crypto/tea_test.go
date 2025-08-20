package crypto

import (
	"bytes"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/crypto/tea"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TEA test data constants
var (
	key16_tea      = []byte("dongle1234567890") // 16 bytes
	testData8_tea  = []byte("12345678")         // 8 bytes (block-aligned)
	testData16_tea = []byte("1234567890123456") // 16 bytes (block-aligned)
	testData_tea   = []byte("hello world")      // 11 bytes (not block-aligned)
)

func TestEncrypter_ByTea(t *testing.T) {
	t.Run("basic_encryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.Equal(t, 8, len(encrypter.dst))
	})

	t.Run("encryption_with_string_input", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewEncrypter().FromString("12345678").ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.Equal(t, 8, len(encrypter.dst))
	})

	t.Run("encryption_with_file_input", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		file := mock.NewFile(testData8_tea, "test.txt")
		encrypter := NewEncrypter().FromFile(file).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.Equal(t, 8, len(encrypter.dst))
	})

	t.Run("streaming_encryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		file := mock.NewFile(testData16_tea, "test.txt")
		encrypter := NewEncrypter().FromFile(file).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.NotNil(t, encrypter.dst)
		assert.Equal(t, 16, len(encrypter.dst))
	})

	t.Run("encryption_with_different_key_sizes", func(t *testing.T) {
		t.Run("16_byte_key", func(t *testing.T) {
			c := cipher.NewTeaCipher()
			c.SetKey(key16_tea)

			encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
			assert.Nil(t, encrypter.Error)
			assert.NotNil(t, encrypter.dst)
		})

		t.Run("invalid_key_size", func(t *testing.T) {
			c := cipher.NewTeaCipher()
			c.SetKey([]byte("short")) // 5 bytes

			encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
			assert.NotNil(t, encrypter.Error)
			assert.Contains(t, encrypter.Error.Error(), "invalid key size 5")
		})
	})

	t.Run("encryption_with_different_rounds", func(t *testing.T) {
		t.Run("32_rounds", func(t *testing.T) {
			c := cipher.NewTeaCipher()
			c.SetKey(key16_tea)
			c.SetRounds(32)

			encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
			assert.Nil(t, encrypter.Error)
			assert.NotNil(t, encrypter.dst)
		})

		t.Run("64_rounds", func(t *testing.T) {
			c := cipher.NewTeaCipher()
			c.SetKey(key16_tea)
			c.SetRounds(64)

			encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
			assert.Nil(t, encrypter.Error)
			assert.NotNil(t, encrypter.dst)
		})
	})

	t.Run("encryption_with_block_aligned_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Test with 8-byte data
		encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 8, len(encrypter.dst))

		// Test with 16-byte data
		encrypter = NewEncrypter().FromBytes(testData16_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 16, len(encrypter.dst))
	})

	t.Run("encryption_with_non_block_aligned_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Test with 11-byte data (not block-aligned)
		encrypter := NewEncrypter().FromBytes(testData_tea).ByTea(*c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid data size 11")
	})

	t.Run("encryption_with_empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewEncrypter().FromBytes([]byte{}).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 0, len(encrypter.dst))
	})

	t.Run("encryption_with_nil_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewEncrypter().FromBytes(nil).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 0, len(encrypter.dst))
	})

	t.Run("encryption_with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := NewEncrypter()
		encrypter.Error = assert.AnError

		result := encrypter.FromBytes(testData8_tea).ByTea(*c)
		assert.Equal(t, assert.AnError, result.Error)
		assert.Nil(t, result.dst)
	})
}

func TestDecrypter_ByTea(t *testing.T) {
	t.Run("basic_decryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt
		encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		encrypted := encrypter.ToRawBytes()

		// Then decrypt
		decrypter := NewDecrypter().FromRawBytes(encrypted).ByTea(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testData8_tea, decrypter.ToBytes())
	})

	t.Run("decryption_with_string_input", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt
		encrypter := NewEncrypter().FromString("12345678").ByTea(*c)
		assert.Nil(t, encrypter.Error)
		encrypted := encrypter.ToRawBytes()

		// Then decrypt
		decrypter := NewDecrypter().FromRawString(string(encrypted)).ByTea(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, "12345678", decrypter.ToString())
	})

	t.Run("decryption_with_file_input", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt
		encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		encrypted := encrypter.ToRawBytes()

		// Then decrypt from file
		file := mock.NewFile(encrypted, "encrypted.bin")
		decrypter := NewDecrypter().FromRawFile(file).ByTea(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testData8_tea, decrypter.ToBytes())
	})

	t.Run("streaming_decryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt
		encrypter := NewEncrypter().FromBytes(testData16_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		encrypted := encrypter.ToRawBytes()

		// Then decrypt from file
		file := mock.NewFile(encrypted, "encrypted.bin")
		decrypter := NewDecrypter().FromRawFile(file).ByTea(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, testData16_tea, decrypter.ToBytes())
	})

	t.Run("decryption_with_different_rounds", func(t *testing.T) {
		t.Run("32_rounds", func(t *testing.T) {
			c := cipher.NewTeaCipher()
			c.SetKey(key16_tea)
			c.SetRounds(32)

			// First encrypt
			encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
			assert.Nil(t, encrypter.Error)
			encrypted := encrypter.ToRawBytes()

			// Then decrypt
			decrypter := NewDecrypter().FromRawBytes(encrypted).ByTea(*c)
			assert.Nil(t, decrypter.Error)
			assert.Equal(t, testData8_tea, decrypter.ToBytes())
		})

		t.Run("64_rounds", func(t *testing.T) {
			c := cipher.NewTeaCipher()
			c.SetKey(key16_tea)
			c.SetRounds(64)

			// First encrypt
			encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
			assert.Nil(t, encrypter.Error)
			encrypted := encrypter.ToRawBytes()

			// Then decrypt
			decrypter := NewDecrypter().FromRawBytes(encrypted).ByTea(*c)
			assert.Nil(t, decrypter.Error)
			assert.Equal(t, testData8_tea, decrypter.ToBytes())
		})
	})

	t.Run("decryption_with_empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := NewDecrypter().FromRawBytes([]byte{}).ByTea(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, 0, len(decrypter.ToBytes()))
	})

	t.Run("decryption_with_nil_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := NewDecrypter().FromRawBytes(nil).ByTea(*c)
		assert.Nil(t, decrypter.Error)
		assert.Equal(t, 0, len(decrypter.ToBytes()))
	})

	t.Run("decryption_with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError

		result := decrypter.FromRawBytes(testData8_tea).ByTea(*c)
		assert.Equal(t, assert.AnError, result.Error)
		assert.Nil(t, result.dst)
	})
}

func TestTea_ErrorHandling(t *testing.T) {
	t.Run("invalid_cipher_configuration", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("")) // Empty key

		encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size 0")
	})

	t.Run("invalid_data_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Try to encrypt non-block-aligned data
		encrypter := NewEncrypter().FromBytes(testData_tea).ByTea(*c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid data size 11")
	})

	t.Run("decryption_with_wrong_key", func(t *testing.T) {
		c1 := cipher.NewTeaCipher()
		c1.SetKey(key16_tea)

		c2 := cipher.NewTeaCipher()
		c2.SetKey([]byte("different1234567")) // Different 16-byte key

		// Encrypt with first key
		encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c1)
		assert.Nil(t, encrypter.Error)
		encrypted := encrypter.ToRawBytes()

		// Try to decrypt with second key
		decrypter := NewDecrypter().FromRawBytes(encrypted).ByTea(*c2)
		assert.Nil(t, decrypter.Error)
		// Should get different result
		assert.NotEqual(t, testData8_tea, decrypter.ToBytes())
	})
}

func TestTea_EdgeCases(t *testing.T) {
	t.Run("empty_and_nil_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Empty data
		encrypter := NewEncrypter().FromBytes([]byte{}).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 0, len(encrypter.dst))

		// Nil data
		encrypter = NewEncrypter().FromBytes(nil).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 0, len(encrypter.dst))
	})

	t.Run("exact_block_size_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// 8-byte data (exact block size)
		encrypter := NewEncrypter().FromBytes(testData8_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 8, len(encrypter.dst))

		// 16-byte data (exact block size)
		encrypter = NewEncrypter().FromBytes(testData16_tea).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 16, len(encrypter.dst))
	})
}

func TestTea_StreamingEdgeCases(t *testing.T) {
	t.Run("streaming_with_empty_reader", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Create empty file
		file := mock.NewFile([]byte{}, "empty.txt")
		encrypter := NewEncrypter().FromFile(file).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 0, len(encrypter.dst))
	})

	t.Run("streaming_with_large_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Create large block-aligned data
		largeData := make([]byte, 1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		file := mock.NewFile(largeData, "large.txt")
		encrypter := NewEncrypter().FromFile(file).ByTea(*c)
		assert.Nil(t, encrypter.Error)
		assert.Equal(t, 1024, len(encrypter.dst))
	})
}

// Test crypto/tea package specific implementations
func TestTeaPackage_NewStdEncrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := tea.NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		encrypter := tea.NewStdEncrypter(*c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size 5")
	})
}

func TestTeaPackage_NewStdDecrypter(t *testing.T) {
	t.Run("valid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := tea.NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		decrypter := tea.NewStdDecrypter(*c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size 5")
	})
}

func TestTeaPackage_Encrypt(t *testing.T) {
	t.Run("valid_encryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := tea.NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt(testData8_tea)
		assert.Nil(t, err)
		assert.Equal(t, 8, len(result))
	})

	t.Run("invalid_data_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := tea.NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)

		_, err := encrypter.Encrypt(testData_tea) // 11 bytes, not block-aligned
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 11")
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		encrypter := tea.NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)

		result, err := encrypter.Encrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})
}

func TestTeaPackage_Decrypt(t *testing.T) {
	t.Run("valid_decryption", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt
		encrypter := tea.NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testData8_tea)
		assert.Nil(t, err)

		// Then decrypt
		decrypter := tea.NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)
		result, err := decrypter.Decrypt(encrypted)
		assert.Nil(t, err)
		assert.Equal(t, testData8_tea, result)
	})

	t.Run("invalid_data_size", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := tea.NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)

		_, err := decrypter.Decrypt(testData_tea) // 11 bytes, not block-aligned
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 11")
	})

	t.Run("empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		decrypter := tea.NewStdDecrypter(*c)
		assert.Nil(t, decrypter.Error)

		result, err := decrypter.Decrypt([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(result))
	})
}

func TestTeaPackage_StreamEncrypter(t *testing.T) {
	t.Run("new_stream_encrypter", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := tea.NewStreamEncrypter(writer, *c)
		assert.Nil(t, streamEncrypter.(*tea.StreamEncrypter).Error)
	})

	t.Run("new_stream_encrypter_invalid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		writer := &bytes.Buffer{}
		streamEncrypter := tea.NewStreamEncrypter(writer, *c)
		assert.NotNil(t, streamEncrypter.(*tea.StreamEncrypter).Error)
		assert.Contains(t, streamEncrypter.(*tea.StreamEncrypter).Error.Error(), "invalid key size 5")
	})

	t.Run("write_complete_blocks", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := tea.NewStreamEncrypter(writer, *c)
		assert.Nil(t, streamEncrypter.(*tea.StreamEncrypter).Error)

		// Write 8-byte data (complete block)
		n, err := streamEncrypter.Write(testData8_tea)
		assert.Nil(t, err)
		assert.Equal(t, 8, n)

		// Close
		err = streamEncrypter.Close()
		assert.Nil(t, err)
	})

	t.Run("write_incomplete_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := tea.NewStreamEncrypter(writer, *c)
		assert.Nil(t, streamEncrypter.(*tea.StreamEncrypter).Error)

		// Write 5-byte data (incomplete block)
		_, err := streamEncrypter.Write([]byte("12345"))
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "invalid data size 5")
	})

	t.Run("write_empty_data", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := tea.NewStreamEncrypter(writer, *c)
		assert.Nil(t, streamEncrypter.(*tea.StreamEncrypter).Error)

		// Write empty data
		n, err := streamEncrypter.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write_with_existing_error", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := tea.NewStreamEncrypter(writer, *c)
		assert.Nil(t, streamEncrypter.(*tea.StreamEncrypter).Error)

		// Set an error
		streamEncrypter.(*tea.StreamEncrypter).Error = assert.AnError

		// Try to write
		_, err := streamEncrypter.Write(testData8_tea)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("close_with_closer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Create a mock closer
		mockCloser := &mockCloser{}
		streamEncrypter := tea.NewStreamEncrypter(mockCloser, *c)
		assert.Nil(t, streamEncrypter.(*tea.StreamEncrypter).Error)

		// Close
		err := streamEncrypter.Close()
		assert.Nil(t, err)
		assert.True(t, mockCloser.closed)
	})

	t.Run("close_without_closer", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		writer := &bytes.Buffer{}
		streamEncrypter := tea.NewStreamEncrypter(writer, *c)
		assert.Nil(t, streamEncrypter.(*tea.StreamEncrypter).Error)

		// Close
		err := streamEncrypter.Close()
		assert.Nil(t, err)
	})
}

// mockCloser is a mock implementation of io.Closer for testing
type mockCloser struct {
	closed bool
}

func (m *mockCloser) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockCloser) Close() error {
	m.closed = true
	return nil
}

func TestTeaPackage_StreamDecrypter(t *testing.T) {
	t.Run("new_stream_decrypter", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		reader := bytes.NewReader(testData8_tea)
		streamDecrypter := tea.NewStreamDecrypter(reader, *c)
		assert.Nil(t, streamDecrypter.(*tea.StreamDecrypter).Error)
	})

	t.Run("new_stream_decrypter_invalid_key", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey([]byte("short")) // 5 bytes

		reader := bytes.NewReader(testData8_tea)
		streamDecrypter := tea.NewStreamDecrypter(reader, *c)
		assert.NotNil(t, streamDecrypter.(*tea.StreamDecrypter).Error)
		assert.Contains(t, streamDecrypter.(*tea.StreamDecrypter).Error.Error(), "invalid key size 5")
	})

	t.Run("read_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// First encrypt some data
		encrypter := tea.NewStdEncrypter(*c)
		assert.Nil(t, encrypter.Error)
		encrypted, err := encrypter.Encrypt(testData8_tea)
		assert.Nil(t, err)

		// Then create stream decrypter
		reader := bytes.NewReader(encrypted)
		streamDecrypter := tea.NewStreamDecrypter(reader, *c)
		assert.Nil(t, streamDecrypter.(*tea.StreamDecrypter).Error)

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
		streamDecrypter := tea.NewStreamDecrypter(reader, *c)
		assert.Nil(t, streamDecrypter.(*tea.StreamDecrypter).Error)

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
		streamDecrypter := tea.NewStreamDecrypter(reader, *c)
		assert.Nil(t, streamDecrypter.(*tea.StreamDecrypter).Error)

		// Set an error
		streamDecrypter.(*tea.StreamDecrypter).Error = assert.AnError

		// Try to read
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("read_partial_block", func(t *testing.T) {
		c := cipher.NewTeaCipher()
		c.SetKey(key16_tea)

		// Create a reader that returns partial data
		partialReader := &partialReader{data: []byte("12345")}
		streamDecrypter := tea.NewStreamDecrypter(partialReader, *c)
		assert.Nil(t, streamDecrypter.(*tea.StreamDecrypter).Error)

		// Try to read
		buffer := make([]byte, 8)
		_, err := streamDecrypter.Read(buffer)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unexpected EOF")
	})
}

// partialReader is a mock reader that returns partial data
type partialReader struct {
	data []byte
	pos  int
}

func (p *partialReader) Read(buf []byte) (n int, err error) {
	if p.pos >= len(p.data) {
		return 0, io.EOF
	}
	n = copy(buf, p.data[p.pos:])
	p.pos += n
	return n, nil
}

func TestTeaPackage_Errors(t *testing.T) {
	t.Run("key_size_error", func(t *testing.T) {
		err := tea.KeySizeError(5)
		assert.Contains(t, err.Error(), "invalid key size 5")
		assert.Contains(t, err.Error(), "must be exactly 16 bytes")
	})

	t.Run("encrypt_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := tea.EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to encrypt data")
		assert.Equal(t, originalErr, err.Unwrap())
	})

	t.Run("decrypt_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := tea.DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to decrypt data")
		assert.Equal(t, originalErr, err.Unwrap())
	})

	t.Run("write_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := tea.WriteError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to write encrypted data")
		assert.Equal(t, originalErr, err.Unwrap())
	})

	t.Run("read_error", func(t *testing.T) {
		originalErr := assert.AnError
		err := tea.ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to read encrypted data")
		assert.Equal(t, originalErr, err.Unwrap())
	})

	t.Run("invalid_data_size_error", func(t *testing.T) {
		err := tea.InvalidDataSizeError{Size: 11}
		assert.Contains(t, err.Error(), "invalid data size 11")
		assert.Contains(t, err.Error(), "must be a multiple of 8 bytes")
	})
}

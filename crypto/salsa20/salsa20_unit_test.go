package salsa20

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data constants
var (
	key32Salsa20    = []byte("dongle12345678901234567890123456") // 32 bytes
	nonce8Salsa20   = []byte("12345678")                         // 8 bytes
	testdataSalsa20 = []byte("hello world")                      // 11 bytes
	testdataEmpty   = []byte("")                                 // 0 bytes
	testdataLong    = []byte("This is a longer test message for Salsa20 encryption and decryption testing")
)

func TestNewStdEncrypter(t *testing.T) {
	t.Run("valid_key_and_nonce", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid_nonce_size", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce([]byte("short")) // 5 bytes

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestNewStdDecrypter(t *testing.T) {
	t.Run("valid_key_and_nonce", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStdDecrypter(c)
		assert.Nil(t, decrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid_nonce_size", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce([]byte("short")) // 5 bytes

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestStdEncrypter_Encrypt(t *testing.T) {
	t.Run("successful_encryption", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testdataSalsa20)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, len(testdataSalsa20), len(result))
		assert.NotEqual(t, testdataSalsa20, result) // Should be encrypted
	})

	t.Run("encrypt_empty_data", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testdataEmpty)
		assert.NoError(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("encrypt_with_existing_error", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // Invalid key
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt(testdataSalsa20)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, encrypter.Error, err)
	})
}

func TestStdDecrypter_Decrypt(t *testing.T) {
	t.Run("successful_decryption", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		// First encrypt some data
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testdataSalsa20)
		assert.NoError(t, err)

		// Then decrypt it
		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, testdataSalsa20, result)
	})

	t.Run("decrypt_empty_data", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(testdataEmpty)
		assert.NoError(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("decrypt_with_existing_error", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // Invalid key
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt(testdataSalsa20)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, decrypter.Error, err)
	})
}

func TestNewStreamEncrypter(t *testing.T) {
	t.Run("valid_key_and_nonce", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.Nil(t, streamEncrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.Contains(t, streamEncrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid_nonce_size", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce([]byte("short")) // 5 bytes

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.Contains(t, streamEncrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestStreamEncrypter_Write(t *testing.T) {
	t.Run("successful_write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testdataSalsa20)
		assert.NoError(t, err)
		assert.Equal(t, len(testdataSalsa20), n)
		assert.NotEmpty(t, buf.Bytes())
	})

	t.Run("write_empty_data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testdataEmpty)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
		assert.Empty(t, buf.Bytes())
	})

	t.Run("write_with_existing_error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // Invalid key
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write(testdataSalsa20)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("write_with_writer_error", func(t *testing.T) {
		writer := mock.NewErrorReadWriteCloser(io.ErrClosedPipe)
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(writer, c)
		n, err := encrypter.Write(testdataSalsa20)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestStreamEncrypter_Close(t *testing.T) {
	t.Run("close_with_closer", func(t *testing.T) {
		closer := mock.NewErrorReadWriteCloser(nil)
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(closer, c)
		err := encrypter.Close()
		assert.NoError(t, err)
	})

	t.Run("close_without_closer", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.NoError(t, err)
	})

	t.Run("close_with_existing_error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // Invalid key
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStreamEncrypter(&buf, c)
		err := encrypter.Close()
		assert.Error(t, err)
		assert.Equal(t, encrypter.(*StreamEncrypter).Error, err)
	})
}

func TestNewStreamDecrypter(t *testing.T) {
	t.Run("valid_key_and_nonce", func(t *testing.T) {
		reader := bytes.NewReader(testdataSalsa20)
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.Nil(t, streamDecrypter.Error)
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		reader := bytes.NewReader(testdataSalsa20)
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // 5 bytes
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.Contains(t, streamDecrypter.Error.Error(), "invalid key size 5")
	})

	t.Run("invalid_nonce_size", func(t *testing.T) {
		reader := bytes.NewReader(testdataSalsa20)
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce([]byte("short")) // 5 bytes

		decrypter := NewStreamDecrypter(reader, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.Contains(t, streamDecrypter.Error.Error(), "invalid nonce size 5")
	})
}

func TestStreamDecrypter_Read(t *testing.T) {
	t.Run("successful_read", func(t *testing.T) {
		// First encrypt some data
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testdataSalsa20)
		assert.NoError(t, err)

		// Then decrypt it using stream decrypter
		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)

		buf := make([]byte, len(testdataSalsa20))
		n, err := decrypter.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, len(testdataSalsa20), n)
		assert.Equal(t, testdataSalsa20, buf)
	})

	t.Run("read_empty_data", func(t *testing.T) {
		reader := bytes.NewReader(testdataEmpty)
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read_with_existing_error", func(t *testing.T) {
		reader := bytes.NewReader(testdataSalsa20)
		c := cipher.NewSalsa20Cipher()
		c.SetKey([]byte("short")) // Invalid key
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read_with_reader_error", func(t *testing.T) {
		reader := mock.NewErrorReadWriteCloser(io.ErrClosedPipe)
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		decrypter := NewStreamDecrypter(reader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Error(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read_multiple_chunks", func(t *testing.T) {
		// First encrypt some data
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testdataSalsa20)
		assert.NoError(t, err)

		// Then decrypt it using stream decrypter with multiple reads
		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)

		// Read in small chunks
		chunkSize := 3
		var result []byte
		for {
			buf := make([]byte, chunkSize)
			n, err := decrypter.Read(buf)
			if err == io.EOF {
				break
			}
			assert.NoError(t, err)
			result = append(result, buf[:n]...)
		}
		assert.Equal(t, testdataSalsa20, result)
	})

	t.Run("read_after_eof", func(t *testing.T) {
		// First encrypt some data
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testdataSalsa20)
		assert.NoError(t, err)

		// Then decrypt it using stream decrypter
		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)

		// Read all data first
		buf := make([]byte, len(testdataSalsa20))
		n, err := decrypter.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, len(testdataSalsa20), n)
		assert.Equal(t, testdataSalsa20, buf)

		// Try to read again after EOF
		buf2 := make([]byte, 10)
		n2, err2 := decrypter.Read(buf2)
		assert.Equal(t, io.EOF, err2)
		assert.Equal(t, 0, n2)
	})

	t.Run("read_with_zero_buffer", func(t *testing.T) {
		// First encrypt some data
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(testdataSalsa20)
		assert.NoError(t, err)

		// Then decrypt it using stream decrypter with zero buffer
		reader := bytes.NewReader(encrypted)
		decrypter := NewStreamDecrypter(reader, c)

		// Read with zero buffer
		buf := make([]byte, 0)
		n, err := decrypter.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("KeySizeError", func(t *testing.T) {
		err := KeySizeError(16)
		assert.Contains(t, err.Error(), "invalid key size 16")
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
	})

	t.Run("NonceSizeError", func(t *testing.T) {
		err := NonceSizeError(4)
		assert.Contains(t, err.Error(), "invalid nonce size 4")
		assert.Contains(t, err.Error(), "must be exactly 8 bytes")
	})

	t.Run("EncryptError", func(t *testing.T) {
		originalErr := errors.New("test error")
		err := EncryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to encrypt data")
		assert.Contains(t, err.Error(), "test error")
	})

	t.Run("DecryptError", func(t *testing.T) {
		originalErr := errors.New("test error")
		err := DecryptError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to decrypt data")
		assert.Contains(t, err.Error(), "test error")
	})

	t.Run("WriteError", func(t *testing.T) {
		originalErr := errors.New("test error")
		err := WriteError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to write encrypted data")
		assert.Contains(t, err.Error(), "test error")
	})

	t.Run("ReadError", func(t *testing.T) {
		originalErr := errors.New("test error")
		err := ReadError{Err: originalErr}
		assert.Contains(t, err.Error(), "failed to read encrypted data")
		assert.Contains(t, err.Error(), "test error")
	})
}

// Test data generated using Python pycryptodome library for validation
var pythonTestCases = []struct {
	name                                      string
	key, nonce, plaintext, expectedCiphertext []byte
}{
	{
		name:               "basic_encryption",
		key:                []byte("dongle12345678901234567890123456"),
		nonce:              []byte("12345678"),
		plaintext:          []byte("hello world"),
		expectedCiphertext: []byte{95, 189, 148, 107, 157, 239, 23, 17, 143, 154, 196},
	},
	{
		name:               "empty_plaintext",
		key:                []byte("dongle12345678901234567890123456"),
		nonce:              []byte("12345678"),
		plaintext:          []byte{},
		expectedCiphertext: []byte{},
	},
	{
		name:               "long_plaintext",
		key:                []byte("dongle12345678901234567890123456"),
		nonce:              []byte("12345678"),
		plaintext:          []byte("This is a longer test message for Salsa20 encryption and decryption testing"),
		expectedCiphertext: []byte{99, 176, 145, 116, 210, 166, 19, 94, 156, 214, 204, 199, 101, 107, 239, 107, 94, 69, 139, 163, 243, 194, 108, 80, 124, 29, 144, 97, 62, 125, 255, 165, 224, 191, 237, 172, 132, 176, 119, 133, 117, 2, 196, 57, 247, 236, 149, 143, 182, 150, 176, 76, 225, 188, 75, 32, 104, 37, 190, 218, 125, 117, 197, 230, 210, 72, 237, 22, 78, 147, 104, 103, 131, 160, 29},
	},
	{
		name:               "binary_data",
		key:                []byte("dongle12345678901234567890123456"),
		nonce:              []byte("12345678"),
		plaintext:          []byte{0, 1, 2, 3, 255, 254, 253, 252},
		expectedCiphertext: []byte{55, 217, 250, 4, 13, 49, 157, 130},
	},
	{
		name:               "single_byte",
		key:                []byte("dongle12345678901234567890123456"),
		nonce:              []byte("12345678"),
		plaintext:          []byte("A"),
		expectedCiphertext: []byte{118},
	},
	{
		name:               "unicode_data",
		key:                []byte("dongle12345678901234567890123456"),
		nonce:              []byte("12345678"),
		plaintext:          []byte("Hello 世界 🌍 测试"),
		expectedCiphertext: []byte{127, 189, 148, 107, 157, 239, 132, 198, 107, 17, 53, 36, 43, 252, 21, 149, 243, 17, 8, 101, 12, 10, 174, 160},
	},
}

func TestSalsa20_PythonValidation(t *testing.T) {
	t.Run("validate_against_python_pycryptodome", func(t *testing.T) {
		for _, tc := range pythonTestCases {
			t.Run(tc.name, func(t *testing.T) {
				c := cipher.NewSalsa20Cipher()
				c.SetKey(tc.key)
				c.SetNonce(tc.nonce)

				// Test encryption
				encrypter := NewStdEncrypter(c)
				encrypted, err := encrypter.Encrypt(tc.plaintext)
				assert.NoError(t, err, "Failed to encrypt data for test case: %s", tc.name)
				assert.Equal(t, tc.expectedCiphertext, encrypted, "Encryption result doesn't match Python pycryptodome for test case: %s", tc.name)

				// Test decryption
				decrypter := NewStdDecrypter(c)
				decrypted, err := decrypter.Decrypt(encrypted)
				assert.NoError(t, err, "Failed to decrypt data for test case: %s", tc.name)
				assert.Equal(t, tc.plaintext, decrypted, "Decryption result doesn't match original plaintext for test case: %s", tc.name)
			})
		}
	})
}

func TestSalsa20_Integration(t *testing.T) {
	t.Run("encrypt_decrypt_roundtrip", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		// Test with different data sizes
		testCases := [][]byte{
			testdataEmpty,
			[]byte("a"),
			[]byte("hello"),
			testdataSalsa20,
			testdataLong,
		}

		for _, data := range testCases {
			// Encrypt
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(data)
			assert.NoError(t, err, "Failed to encrypt data: %v", data)
			assert.Equal(t, len(data), len(encrypted))

			// Decrypt
			decrypter := NewStdDecrypter(c)
			decrypted, err := decrypter.Decrypt(encrypted)
			assert.NoError(t, err, "Failed to decrypt data: %v", data)
			assert.Equal(t, data, decrypted)
		}
	})

	t.Run("stream_encrypt_decrypt_roundtrip", func(t *testing.T) {
		c := cipher.NewSalsa20Cipher()
		c.SetKey(key32Salsa20)
		c.SetNonce(nonce8Salsa20)

		// Encrypt using stream encrypter
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		_, err := encrypter.Write(testdataSalsa20)
		assert.NoError(t, err)
		err = encrypter.Close()
		assert.NoError(t, err)

		// Decrypt using stream decrypter
		reader := bytes.NewReader(buf.Bytes())
		decrypter := NewStreamDecrypter(reader, c)
		decrypted := make([]byte, len(testdataSalsa20))
		n, err := decrypter.Read(decrypted)
		assert.NoError(t, err)
		assert.Equal(t, len(testdataSalsa20), n)
		assert.Equal(t, testdataSalsa20, decrypted)
	})
}

package sm4

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for error testing
var (
	key16Error    = []byte("1234567890123456") // SM4 key (16 bytes)
	iv16Error     = []byte("1234567890123456") // 16-byte IV
	testDataError = []byte("hello world")
)

// TestKeySizeError tests the KeySizeError type and its Error() method
func TestKeySizeError(t *testing.T) {
	t.Run("valid key size", func(t *testing.T) {
		// Test that valid key size doesn't trigger KeySizeError in actual usage
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.Nil(t, encrypter.Error) // Should not have KeySizeError for valid keys
	})

	t.Run("invalid key sizes", func(t *testing.T) {
		invalidSizes := []int{0, 1, 8, 15, 17, 23, 25, 31, 33, 64, 128}
		for _, size := range invalidSizes {
			err := KeySizeError(size)
			expected := "crypto/sm4: invalid key size 8, key must be 16 bytes"
			if size == 0 {
				expected = "crypto/sm4: invalid key size 0, key must be 16 bytes"
			} else if size == 1 {
				expected = "crypto/sm4: invalid key size 1, key must be 16 bytes"
			} else if size == 8 {
				expected = "crypto/sm4: invalid key size 8, key must be 16 bytes"
			} else if size == 15 {
				expected = "crypto/sm4: invalid key size 15, key must be 16 bytes"
			} else if size == 17 {
				expected = "crypto/sm4: invalid key size 17, key must be 16 bytes"
			} else if size == 23 {
				expected = "crypto/sm4: invalid key size 23, key must be 16 bytes"
			} else if size == 25 {
				expected = "crypto/sm4: invalid key size 25, key must be 16 bytes"
			} else if size == 31 {
				expected = "crypto/sm4: invalid key size 31, key must be 16 bytes"
			} else if size == 33 {
				expected = "crypto/sm4: invalid key size 33, key must be 16 bytes"
			} else if size == 64 {
				expected = "crypto/sm4: invalid key size 64, key must be 16 bytes"
			} else if size == 128 {
				expected = "crypto/sm4: invalid key size 128, key must be 16 bytes"
			}
			assert.Equal(t, expected, err.Error())
		}
	})

	t.Run("negative key size", func(t *testing.T) {
		err := KeySizeError(-1)
		expected := "crypto/sm4: invalid key size -1, key must be 16 bytes"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("large key size", func(t *testing.T) {
		err := KeySizeError(1000)
		expected := "crypto/sm4: invalid key size 1000, key must be 16 bytes"
		assert.Equal(t, expected, err.Error())
	})
}

// TestEncryptError tests the EncryptError type and its Error() method
func TestEncryptError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := EncryptError{Err: nil}
		expected := "crypto/sm4: encryption failed: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("simple error")
		err := EncryptError{Err: originalErr}
		expected := "crypto/sm4: encryption failed: simple error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("encryption failed: invalid key format")
		err := EncryptError{Err: originalErr}
		expected := "crypto/sm4: encryption failed: encryption failed: invalid key format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with wrapped error", func(t *testing.T) {
		originalErr := errors.New("underlying error")
		wrappedErr := errors.New("wrapped: " + originalErr.Error())
		err := EncryptError{Err: wrappedErr}
		expected := "crypto/sm4: encryption failed: wrapped: underlying error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := EncryptError{Err: originalErr}
		expected := "crypto/sm4: encryption failed: "
		assert.Equal(t, expected, err.Error())
	})
}

// TestDecryptError tests the DecryptError type and its Error() method
func TestDecryptError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := DecryptError{Err: nil}
		expected := "crypto/sm4: decryption failed: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("decryption failed")
		err := DecryptError{Err: originalErr}
		expected := "crypto/sm4: decryption failed: decryption failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("decryption failed: invalid ciphertext format")
		err := DecryptError{Err: originalErr}
		expected := "crypto/sm4: decryption failed: decryption failed: invalid ciphertext format"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with authentication error", func(t *testing.T) {
		originalErr := errors.New("authentication failed")
		err := DecryptError{Err: originalErr}
		expected := "crypto/sm4: decryption failed: authentication failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := DecryptError{Err: originalErr}
		expected := "crypto/sm4: decryption failed: "
		assert.Equal(t, expected, err.Error())
	})
}

// TestReadError tests the ReadError type and its Error() method
func TestReadError(t *testing.T) {
	t.Run("with nil error", func(t *testing.T) {
		err := ReadError{Err: nil}
		expected := "crypto/sm4: read failed: <nil>"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with simple error", func(t *testing.T) {
		originalErr := errors.New("read failed")
		err := ReadError{Err: originalErr}
		expected := "crypto/sm4: read failed: read failed"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with complex error message", func(t *testing.T) {
		originalErr := errors.New("read failed: connection timeout")
		err := ReadError{Err: originalErr}
		expected := "crypto/sm4: read failed: read failed: connection timeout"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with EOF error", func(t *testing.T) {
		originalErr := errors.New("unexpected EOF")
		err := ReadError{Err: originalErr}
		expected := "crypto/sm4: read failed: unexpected EOF"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("with empty error message", func(t *testing.T) {
		originalErr := errors.New("")
		err := ReadError{Err: originalErr}
		expected := "crypto/sm4: read failed: "
		assert.Equal(t, expected, err.Error())
	})
}

// TestErrorIntegration tests error types in actual SM4 operations
func TestErrorIntegration(t *testing.T) {
	t.Run("KeySizeError in StdEncrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("17bytes_key123456"),
			make([]byte, 33),
		}

		for _, key := range invalidKeys {
			c := cipher.NewSm4Cipher(cipher.CBC)
			c.SetKey(key)
			c.SetIV(iv16Error)
			c.SetPadding(cipher.PKCS7)

			encrypter := NewStdEncrypter(c)
			assert.NotNil(t, encrypter)
			assert.NotNil(t, encrypter.Error)
			assert.IsType(t, KeySizeError(0), encrypter.Error)
		}
	})

	t.Run("KeySizeError in StdDecrypter", func(t *testing.T) {
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
		}

		for _, key := range invalidKeys {
			c := cipher.NewSm4Cipher(cipher.CBC)
			c.SetKey(key)

			decrypter := NewStdDecrypter(c)
			assert.NotNil(t, decrypter)
			assert.NotNil(t, decrypter.Error)
			assert.IsType(t, KeySizeError(0), decrypter.Error)
		}
	})

	t.Run("KeySizeError in StreamEncrypter", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		assert.NotNil(t, streamEncrypter.Error)
		assert.IsType(t, KeySizeError(0), streamEncrypter.Error)
	})

	t.Run("KeySizeError in StreamDecrypter", func(t *testing.T) {
		file := mock.NewFile([]byte("test"), "test.txt")
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid"))

		decrypter := NewStreamDecrypter(file, c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		assert.NotNil(t, streamDecrypter.Error)
		assert.IsType(t, KeySizeError(0), streamDecrypter.Error)
	})

	t.Run("ReadError in StreamDecrypter Read", func(t *testing.T) {
		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})

	t.Run("EncryptError in StreamEncrypter Write", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		// Create a stream encrypter with an error
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		// Set an error to trigger EncryptError
		streamEncrypter.Error = errors.New("existing error")

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("DecryptError in StreamDecrypter Read", func(t *testing.T) {
		file := mock.NewFile([]byte("invalid data"), "test.txt")
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid_key_size")) // This will cause a decrypt error

		decrypter := NewStreamDecrypter(file, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, DecryptError{}, err)
	})
}

// TestErrorTypeAssertions tests type assertions for error types
func TestErrorTypeAssertions(t *testing.T) {
	t.Run("KeySizeError type assertion", func(t *testing.T) {
		var err error = KeySizeError(8)
		var keySizeErr KeySizeError
		ok := errors.As(err, &keySizeErr)
		assert.True(t, ok)
		assert.Equal(t, KeySizeError(8), keySizeErr)
	})

	t.Run("EncryptError type assertion", func(t *testing.T) {
		originalErr := errors.New("test error")
		var err error = EncryptError{Err: originalErr}
		var encryptErr EncryptError
		ok := errors.As(err, &encryptErr)
		assert.True(t, ok)
		assert.Equal(t, originalErr, encryptErr.Err)
	})

	t.Run("DecryptError type assertion", func(t *testing.T) {
		originalErr := errors.New("test error")
		var err error = DecryptError{Err: originalErr}
		var decryptErr DecryptError
		ok := errors.As(err, &decryptErr)
		assert.True(t, ok)
		assert.Equal(t, originalErr, decryptErr.Err)
	})

	t.Run("ReadError type assertion", func(t *testing.T) {
		originalErr := errors.New("test error")
		var err error = ReadError{Err: originalErr}
		var readErr ReadError
		ok := errors.As(err, &readErr)
		assert.True(t, ok)
		assert.Equal(t, originalErr, readErr.Err)
	})
}

// TestStdEncrypterErrors tests various error conditions in StdEncrypter
func TestStdEncrypterErrors(t *testing.T) {
	t.Run("invalid key size in StdEncrypter", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // Invalid key size
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		assert.NotNil(t, encrypter.Error)
		assert.Contains(t, encrypter.Error.Error(), "invalid key size")
	})

	t.Run("encryption error in StdEncrypter", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Test with existing error
		encrypter.Error = errors.New("existing error")
		result, err := encrypter.Encrypt(testDataError)
		assert.NotNil(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		result, err := encrypter.Encrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})
}

// TestStdDecrypterErrors tests various error conditions in StdDecrypter
func TestStdDecrypterErrors(t *testing.T) {
	t.Run("invalid key size in StdDecrypter", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // Invalid key size
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		assert.NotNil(t, decrypter.Error)
		assert.Contains(t, decrypter.Error.Error(), "invalid key size")
	})

	t.Run("decryption error in StdDecrypter", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Test with existing error
		decrypter.Error = errors.New("existing error")
		result, err := decrypter.Decrypt(testDataError)
		assert.NotNil(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("decrypt empty data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		result, err := decrypter.Decrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})
}

// TestStreamEncrypterErrors tests various error conditions in StreamEncrypter
func TestStreamEncrypterErrors(t *testing.T) {
	t.Run("invalid key size in StreamEncrypter", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // Invalid key size
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		assert.NotNil(t, encrypter.(*StreamEncrypter).Error)
		assert.Contains(t, encrypter.(*StreamEncrypter).Error.Error(), "invalid key size")
	})

	t.Run("write with existing error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		// Set an existing error
		streamEncrypter.Error = errors.New("existing error")

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("write with empty data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("write with writer error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		// Create a mock writer that always returns an error
		mockWriter := mock.NewErrorReadWriteCloser(errors.New("write failed"))
		encrypter := NewStreamEncrypter(mockWriter, c)

		n, err := encrypter.Write(testDataError)
		assert.Equal(t, 0, n)
		assert.Equal(t, "write failed", err.Error())
	})

	t.Run("close with underlying closer error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		// Use a mock closer that returns an error
		mockCloser := mock.NewCloseErrorWriteCloser(&bytes.Buffer{}, errors.New("close failed"))
		encrypter := NewStreamEncrypter(mockCloser, c)

		err := encrypter.Close()
		assert.NotNil(t, err)
		// The error should be wrapped in EncryptError
		encryptErr, ok := err.(EncryptError)
		assert.True(t, ok)
		assert.Equal(t, "close failed", encryptErr.Err.Error())
	})
}

// TestStreamDecrypterErrors tests various error conditions in StreamDecrypter
func TestStreamDecrypterErrors(t *testing.T) {
	t.Run("invalid key size in StreamDecrypter", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey([]byte("invalid")) // Invalid key size
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader(testDataError), c)
		assert.NotNil(t, decrypter.(*StreamDecrypter).Error)
		assert.Contains(t, decrypter.(*StreamDecrypter).Error.Error(), "invalid key size")
	})

	t.Run("read with existing error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader(testDataError), c)
		streamDecrypter := decrypter.(*StreamDecrypter)
		// Set an existing error
		streamDecrypter.Error = errors.New("existing error")

		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("read with empty data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStreamDecrypter(bytes.NewReader([]byte{}), c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("read with read error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		mockReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		decrypter := NewStreamDecrypter(mockReader, c)
		buf := make([]byte, 10)
		n, err := decrypter.Read(buf)
		assert.Equal(t, 0, n)
		assert.IsType(t, ReadError{}, err)
	})
}

// TestTTransform tests the tTransform function directly
func TestTTransform(t *testing.T) {
	t.Run("tTransform with various inputs", func(t *testing.T) {
		// Test with different input values to ensure tTransform works correctly
		testCases := []struct {
			input    uint32
			expected uint32
		}{
			{0x00000000, 0x5b5b5b5b},
			{0xffffffff, 0x21212121},
			{0x12345678, 0xf32f23e8},
			{0x87654321, 0xb0758a02},
		}

		for _, tc := range testCases {
			result := tTransform(tc.input)
			assert.Equal(t, tc.expected, result, "tTransform(%08x) = %08x, expected %08x", tc.input, result, tc.expected)
		}
	})
}

// TestTPrime tests the tPrime function directly
func TestTPrime(t *testing.T) {
	t.Run("tPrime equivalent with various inputs", func(t *testing.T) {
		// Test with different input values to ensure tPrime works correctly
		testCases := []struct {
			input    uint32
			expected uint32
		}{
			{0x00000000, 0x67676767},
			{0xffffffff, 0x65656565},
			{0x12345678, 0x87cd2df8},
			{0x87654321, 0x8b8a0697},
		}

		for _, tc := range testCases {
			// tPrime(x) == L'(S(x))
			result := lPrimeTransform(sBoxTransform(tc.input))
			assert.Equal(t, tc.expected, result, "L'(S(%08x)) = %08x, expected %08x", tc.input, result, tc.expected)
		}
	})
}

// TestF tests the f function directly
func TestRound(t *testing.T) {
	t.Run("round equivalent with various inputs", func(t *testing.T) {
		// Test with different input values to ensure f function works correctly
		testCases := []struct {
			x0, x1, x2, x3, rk uint32
			expected           uint32
		}{
			{0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x5b5b5b5b},
			{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xa4a4a4a4},
			{0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0, 0x12345678, 0x496f0d23},
		}

		for _, tc := range testCases {
			// round(x0,x1,x2,x3,rk) == x0 ^ T(x1^x2^x3^rk)
			result := tc.x0 ^ tTransform(tc.x1^tc.x2^tc.x3^tc.rk)
			assert.Equal(t, tc.expected, result, "x0 ^ T(x1^x2^x3^rk) (%08x, %08x, %08x, %08x, %08x) = %08x, expected %08x",
				tc.x0, tc.x1, tc.x2, tc.x3, tc.rk, result, tc.expected)
		}
	})
}

// TestNewCipherErrorPaths tests error paths in NewCipher function
func TestNewCipherErrorPaths(t *testing.T) {
	t.Run("NewCipher with invalid key size", func(t *testing.T) {
		// Test with various invalid key sizes
		invalidKeys := [][]byte{
			nil,
			{},
			[]byte("short"),
			[]byte("this_key_is_way_too_long_and_invalid"),
		}

		for _, key := range invalidKeys {
			block, err := NewCipher(key)
			assert.Nil(t, block)
			assert.NotNil(t, err)
			assert.IsType(t, KeySizeError(0), err)
		}
	})

	t.Run("NewCipher with valid key size", func(t *testing.T) {
		validKey := []byte("1234567890123456") // 16 bytes
		block, err := NewCipher(validKey)
		assert.NotNil(t, block)
		assert.Nil(t, err)
		assert.IsType(t, &sm4Cipher{}, block)
	})
}

// TestEncryptPanicPaths tests panic paths in Encrypt function
func TestEncryptPanicPaths(t *testing.T) {
	t.Run("Encrypt with short source", func(t *testing.T) {
		key := []byte("1234567890123456")
		block, _ := NewCipher(key)

		src := []byte("short") // Less than BlockSize
		dst := make([]byte, BlockSize)

		assert.PanicsWithValue(t, "sm4: input not full block", func() {
			block.Encrypt(dst, src)
		})
	})

	t.Run("Encrypt with short destination", func(t *testing.T) {
		key := []byte("1234567890123456")
		block, _ := NewCipher(key)

		src := make([]byte, BlockSize)
		dst := []byte("short") // Less than BlockSize

		assert.PanicsWithValue(t, "sm4: output not full block", func() {
			block.Encrypt(dst, src)
		})
	})

	t.Run("Encrypt with valid buffers", func(t *testing.T) {
		key := []byte("1234567890123456")
		block, _ := NewCipher(key)

		src := make([]byte, BlockSize)
		dst := make([]byte, BlockSize)

		// Should not panic with valid buffers
		assert.NotPanics(t, func() {
			block.Encrypt(dst, src)
		})
		assert.Len(t, dst, BlockSize)
	})
}

// TestDecryptPanicPaths tests panic paths in Decrypt function
func TestDecryptPanicPaths(t *testing.T) {
	t.Run("Decrypt with short source", func(t *testing.T) {
		key := []byte("1234567890123456")
		block, _ := NewCipher(key)

		src := []byte("short") // Less than BlockSize
		dst := make([]byte, BlockSize)

		assert.PanicsWithValue(t, "crypto/sm4: input not full block", func() {
			block.Decrypt(dst, src)
		})
	})

	t.Run("Decrypt with short destination", func(t *testing.T) {
		key := []byte("1234567890123456")
		block, _ := NewCipher(key)

		src := make([]byte, BlockSize)
		dst := []byte("short") // Less than BlockSize

		assert.PanicsWithValue(t, "crypto/sm4: output not full block", func() {
			block.Decrypt(dst, src)
		})
	})

	t.Run("Decrypt with valid buffers", func(t *testing.T) {
		key := []byte("1234567890123456")
		block, _ := NewCipher(key)

		src := make([]byte, BlockSize)
		dst := make([]byte, BlockSize)

		// Should not panic with valid buffers
		assert.NotPanics(t, func() {
			block.Decrypt(dst, src)
		})
		assert.Len(t, dst, BlockSize)
	})
}

// TestStdEncrypterErrorPaths tests error paths in StdEncrypter methods
func TestStdEncrypterErrorPaths(t *testing.T) {
	t.Run("StdEncrypter Encrypt with existing error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)
		// Manually set an error to test error path
		encrypter.Error = errors.New("existing error")

		result, err := encrypter.Encrypt([]byte("test"))
		assert.Nil(t, result)
		assert.Equal(t, "existing error", err.Error())
	})
}

// TestStdDecrypterErrorPaths tests error paths in StdDecrypter methods
func TestStdDecrypterErrorPaths(t *testing.T) {
	t.Run("StdDecrypter Decrypt with existing error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)
		// Manually set an error to test error path
		decrypter.Error = errors.New("existing error")

		result, err := decrypter.Decrypt([]byte("test"))
		assert.Nil(t, result)
		assert.Equal(t, "existing error", err.Error())
	})
}

// TestStreamEncrypterCloseError tests error paths in StreamEncrypter Close method
func TestStreamEncrypterCloseError(t *testing.T) {
	t.Run("StreamEncrypter Close with existing error", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter := encrypter.(*StreamEncrypter)
		// Manually set an error to test error path
		streamEncrypter.Error = errors.New("existing error")

		err := encrypter.Close()
		assert.Equal(t, "existing error", err.Error())
	})

	t.Run("StreamEncrypter Close with underlying closer error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		// Use a mock closer that returns an error
		mockCloser := mock.NewCloseErrorWriteCloser(&bytes.Buffer{}, errors.New("close error"))
		encrypter := NewStreamEncrypter(mockCloser, c)

		err := encrypter.Close()
		assert.NotNil(t, err)
		assert.IsType(t, EncryptError{}, err)
	})
}

// mockBlock is a mock implementation of cipher.Block for testing error paths
type mockBlock struct {
	blockSize int
	encrypt   func(dst, src []byte)
	decrypt   func(dst, src []byte)
}

func (m *mockBlock) BlockSize() int { return m.blockSize }
func (m *mockBlock) Encrypt(dst, src []byte) {
	if m.encrypt != nil {
		m.encrypt(dst, src)
	} else {
		copy(dst, src)
	}
}
func (m *mockBlock) Decrypt(dst, src []byte) {
	if m.decrypt != nil {
		m.decrypt(dst, src)
	} else {
		copy(dst, src)
	}
}

// TestStdEncrypterEncryptError tests error paths in StdEncrypter Encrypt method
func TestStdEncrypterEncryptError(t *testing.T) {
	t.Run("StdEncrypter Encrypt with empty data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)

		result, err := encrypter.Encrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("StdEncrypter Encrypt with cipher error - empty IV", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		// Don't set IV to trigger EmptyIVError
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStdEncrypter(c)

		// Override the block to bypass NewCipher validation
		block, _ := NewCipher(key16Error)
		encrypter.block = block

		result, err := encrypter.Encrypt([]byte("test data"))
		assert.Nil(t, result)
		assert.IsType(t, EncryptError{}, err)
	})
}

// TestStdDecrypterDecryptError tests error paths in StdDecrypter Decrypt method
func TestStdDecrypterDecryptError(t *testing.T) {
	t.Run("StdDecrypter Decrypt with empty data", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)

		result, err := decrypter.Decrypt([]byte{})
		assert.Empty(t, result)
		assert.Nil(t, err)
	})

	t.Run("StdDecrypter Decrypt with cipher error - empty IV", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		// Don't set IV to trigger EmptyIVError
		c.SetPadding(cipher.PKCS7)

		decrypter := NewStdDecrypter(c)

		// Override the block to bypass NewCipher validation
		block, _ := NewCipher(key16Error)
		decrypter.block = block

		result, err := decrypter.Decrypt([]byte("test data"))
		assert.Nil(t, result)
		assert.IsType(t, DecryptError{}, err)
	})
}

// TestStreamEncrypterWriteError tests error paths in StreamEncrypter Write method
func TestStreamEncrypterWriteError(t *testing.T) {
	t.Run("StreamEncrypter Write with empty data", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)

		n, err := encrypter.Write([]byte{})
		assert.Equal(t, 0, n)
		assert.Nil(t, err)
	})

	t.Run("StreamEncrypter Write with writer error", func(t *testing.T) {
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		c.SetIV(iv16Error)
		c.SetPadding(cipher.PKCS7)

		// Use a mock writer that returns an error
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		encrypter := NewStreamEncrypter(errorWriter, c)

		n, err := encrypter.Write([]byte("test data"))
		assert.Equal(t, 0, n)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("StreamEncrypter Write with cipher error - empty IV", func(t *testing.T) {
		var buf bytes.Buffer
		c := cipher.NewSm4Cipher(cipher.CBC)
		c.SetKey(key16Error)
		// Don't set IV to trigger EmptyIVError
		c.SetPadding(cipher.PKCS7)

		encrypter := NewStreamEncrypter(&buf, c)

		// Override the block to bypass NewCipher validation
		block, _ := NewCipher(key16Error)
		streamEncrypter := encrypter.(*StreamEncrypter)
		streamEncrypter.block = block

		n, err := encrypter.Write([]byte("test data"))
		assert.Equal(t, 0, n)
		assert.IsType(t, EncryptError{}, err)
	})
}

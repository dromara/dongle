package mock

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorHasher(t *testing.T) {
	t.Run("test NewErrorHasher", func(t *testing.T) {
		testErr := errors.New("hash write error")
		hasher := NewErrorHasher(testErr)

		assert.NotNil(t, hasher)
		assert.Equal(t, testErr, hasher.writeErr)
	})

	t.Run("test Write with error", func(t *testing.T) {
		testErr := errors.New("hash write error")
		hasher := NewErrorHasher(testErr)

		data := []byte("test data")
		n, err := hasher.Write(data)

		assert.Equal(t, 0, n)
		assert.Equal(t, testErr, err)
	})

	t.Run("test Write without error", func(t *testing.T) {
		hasher := NewErrorHasher(nil)

		data := []byte("test data")
		n, err := hasher.Write(data)

		assert.Equal(t, len(data), n)
		assert.NoError(t, err)
	})

	t.Run("test Sum method without error", func(t *testing.T) {
		hasher := NewErrorHasher(nil)

		result := hasher.Sum([]byte("prefix"))
		// Should return prefix + 32 bytes of hash
		assert.Equal(t, 38, len(result))
		assert.Equal(t, []byte("prefix"), result[:6])
		// Check that the hash part is not all zeros
		hashPart := result[6:]
		assert.Equal(t, 32, len(hashPart))
		// Verify hash values are sequential starting from 1
		for i, b := range hashPart {
			assert.Equal(t, byte(i+1), b)
		}
	})

	t.Run("test Sum method with short error message", func(t *testing.T) {
		testErr := errors.New("test error")
		hasher := NewErrorHasher(testErr)

		result := hasher.Sum([]byte("prefix"))
		// Should return prefix + 32 bytes of hash
		assert.Equal(t, 38, len(result))
		assert.Equal(t, []byte("prefix"), result[:6])
		// Check that the hash part is based on error message
		hashPart := result[6:]
		assert.Equal(t, 32, len(hashPart))
		// First few bytes should match error message
		errStr := testErr.Error()
		for i := 0; i < len(errStr); i++ {
			assert.Equal(t, errStr[i], hashPart[i])
		}
		// Remaining bytes should be filled with byte(i)
		for i := len(errStr); i < 32; i++ {
			assert.Equal(t, byte(i), hashPart[i])
		}
	})

	t.Run("test Sum method with long error message", func(t *testing.T) {
		// Create a very long error message to test the else branch in Sum method
		longErrMsg := ""
		for range 50 {
			longErrMsg += "a"
		}
		testErr := errors.New(longErrMsg)
		hasher := NewErrorHasher(testErr)

		result := hasher.Sum([]byte("prefix"))
		// Should return prefix + 32 bytes of hash
		assert.Equal(t, 38, len(result))
		assert.Equal(t, []byte("prefix"), result[:6])
		// Check that the hash part is based on error message
		hashPart := result[6:]
		assert.Equal(t, 32, len(hashPart))
		// First 32 bytes should match error message
		errStr := testErr.Error()
		for i := range 32 {
			assert.Equal(t, errStr[i], hashPart[i])
		}
	})

	t.Run("test Sum method with exactly 32 byte error message", func(t *testing.T) {
		// Create an error message that is exactly 32 bytes long
		longErrMsg := ""
		for range 32 {
			longErrMsg += "b"
		}
		testErr := errors.New(longErrMsg)
		hasher := NewErrorHasher(testErr)

		result := hasher.Sum(nil)
		// Should return exactly 32 bytes of hash
		assert.Equal(t, 32, len(result))
		// All 32 bytes should match error message
		errStr := testErr.Error()
		for i := range 32 {
			assert.Equal(t, errStr[i], result[i])
		}
	})

	t.Run("test Sum method with empty prefix", func(t *testing.T) {
		hasher := NewErrorHasher(nil)

		result := hasher.Sum(nil)
		// Should return just the 32 bytes of hash
		assert.Equal(t, 32, len(result))
		// Verify hash values are sequential starting from 1
		for i, b := range result {
			assert.Equal(t, byte(i+1), b)
		}
	})

	t.Run("test Reset method", func(t *testing.T) {
		hasher := NewErrorHasher(nil)
		// Reset should not panic and should be no-op
		assert.NotPanics(t, func() {
			hasher.Reset()
		})
		// After reset, the hasher should still work the same
		data := []byte("test")
		n, err := hasher.Write(data)
		assert.Equal(t, 4, n)
		assert.NoError(t, err)
	})

	t.Run("test Size method", func(t *testing.T) {
		hasher := NewErrorHasher(nil)
		assert.Equal(t, 32, hasher.Size())
	})

	t.Run("test BlockSize method", func(t *testing.T) {
		hasher := NewErrorHasher(nil)
		assert.Equal(t, 64, hasher.BlockSize())
	})

	t.Run("test ErrorHasher with different error types", func(t *testing.T) {
		// Test with different error messages
		errors := []error{
			errors.New("error 1"),
			errors.New("different error message"),
			errors.New(""),
		}

		for _, testErr := range errors {
			hasher := NewErrorHasher(testErr)
			assert.Equal(t, testErr, hasher.writeErr)

			// Test Write returns the error
			n, err := hasher.Write([]byte("test"))
			assert.Equal(t, 0, n)
			assert.Equal(t, testErr, err)

			// Test Sum still works
			result := hasher.Sum(nil)
			assert.Equal(t, 32, len(result))
		}
	})
}

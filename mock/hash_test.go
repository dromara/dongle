package mock

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
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

	t.Run("test Sum method", func(t *testing.T) {
		hasher := NewErrorHasher(nil)

		result := hasher.Sum([]byte("prefix"))
		assert.Equal(t, []byte("mock hash"), result)
	})

	t.Run("test Reset method", func(t *testing.T) {
		hasher := NewErrorHasher(nil)
		// Reset should not panic and should be no-op
		hasher.Reset()
	})

	t.Run("test Size method", func(t *testing.T) {
		hasher := NewErrorHasher(nil)
		assert.Equal(t, 32, hasher.Size())
	})

	t.Run("test BlockSize method", func(t *testing.T) {
		hasher := NewErrorHasher(nil)
		assert.Equal(t, 64, hasher.BlockSize())
	})
}

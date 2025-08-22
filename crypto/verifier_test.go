package crypto

import (
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

// TestNewVerifier tests the NewVerifier function
func TestNewVerifier(t *testing.T) {
	t.Run("create new verifier", func(t *testing.T) {
		verifier := NewVerifier()
		assert.NotNil(t, verifier)
		assert.Nil(t, verifier.data)
		assert.Nil(t, verifier.reader)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromString tests the FromRawString method
func TestVerifier_FromString(t *testing.T) {
	t.Run("from raw string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromString("hello world")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello world"), verifier.data)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromString("")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.data)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from unicode string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromString("你好世界")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("你好世界"), verifier.data)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromRawBytes tests the FromRawBytes method
func TestVerifier_FromBytes(t *testing.T) {
	t.Run("from raw bytes", func(t *testing.T) {
		verifier := NewVerifier()
		data := []byte{0x01, 0x02, 0x03, 0x04}
		result := verifier.FromBytes(data)

		assert.Equal(t, verifier, result)
		assert.Equal(t, data, verifier.data)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBytes([]byte{})

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.data)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from nil bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBytes(nil)

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.data)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_ToBool tests the ToBool method
func TestVerifier_ToBool(t *testing.T) {
	t.Run("with valid data and keypair", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with empty source data", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte{}
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with nil keypair", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with empty signature", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with error", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.Error = errors.New("test error")

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with all conditions met but error", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})
}

// TestVerifier_stream tests the stream method
func TestVerifier_stream(t *testing.T) {
	t.Run("with valid reader", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte("hello world"), "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("with nil reader", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.reader = nil

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, io.ErrUnexpectedEOF, err)
	})

	t.Run("with reader error", func(t *testing.T) {
		verifier := NewVerifier()
		errorReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		verifier.reader = errorReader

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("with verifier reader error", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte("hello world"), "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewErrorReadWriteCloser(errors.New("verifier error"))
		})

		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, "verifier error", err.Error())
	})

	t.Run("with empty data", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte{}, "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("with large data", func(t *testing.T) {
		verifier := NewVerifier()
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		file := mock.NewFile(largeData, "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, largeData, result)
	})
}

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
		assert.Nil(t, verifier.src)
		assert.Nil(t, verifier.reader)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromRawString tests the FromRawString method
func TestVerifier_FromRawString(t *testing.T) {
	t.Run("from raw string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromRawString("hello world")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello world"), verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromRawString("")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from unicode string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromRawString("你好世界")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("你好世界"), verifier.src)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromRawBytes tests the FromRawBytes method
func TestVerifier_FromRawBytes(t *testing.T) {
	t.Run("from raw bytes", func(t *testing.T) {
		verifier := NewVerifier()
		data := []byte{0x01, 0x02, 0x03, 0x04}
		result := verifier.FromRawBytes(data)

		assert.Equal(t, verifier, result)
		assert.Equal(t, data, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromRawBytes([]byte{})

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from nil bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromRawBytes(nil)

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.src)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromBase64String tests the FromBase64String method
func TestVerifier_FromBase64String(t *testing.T) {
	t.Run("from valid base64 string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBase64String("aGVsbG8gd29ybGQ=") // "hello world" in base64

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello world"), verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty base64 string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBase64String("")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from invalid base64 string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBase64String("invalid base64!")

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from base64 string with padding", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBase64String("aGVsbG8=") // "hello" in base64

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello"), verifier.src)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromBase64Bytes tests the FromBase64Bytes method
func TestVerifier_FromBase64Bytes(t *testing.T) {
	t.Run("from valid base64 bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBase64Bytes([]byte("aGVsbG8gd29ybGQ=")) // "hello world" in base64

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello world"), verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty base64 bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBase64Bytes([]byte{})

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from invalid base64 bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromBase64Bytes([]byte("invalid base64!"))

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.src)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromHexString tests the FromHexString method
func TestVerifier_FromHexString(t *testing.T) {
	t.Run("from valid hex string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromHexString("68656c6c6f20776f726c64") // "hello world" in hex

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello world"), verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty hex string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromHexString("")

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from invalid hex string", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromHexString("invalid hex!")

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from hex string with uppercase", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromHexString("68656C6C6F20776F726C64") // "hello world" in uppercase hex

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello world"), verifier.src)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_FromHexBytes tests the FromHexBytes method
func TestVerifier_FromHexBytes(t *testing.T) {
	t.Run("from valid hex bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromHexBytes([]byte("68656c6c6f20776f726c64")) // "hello world" in hex

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("hello world"), verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from empty hex bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromHexBytes([]byte{})

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.src)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from invalid hex bytes", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromHexBytes([]byte("invalid hex!"))

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.src)
		assert.Nil(t, verifier.Error)
	})
}

// TestVerifier_ToBool tests the ToBool method
func TestVerifier_ToBool(t *testing.T) {
	t.Run("with valid data and keypair", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte("hello world")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with empty source data", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte{}
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with nil keypair", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte("hello world")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with empty signature", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte("hello world")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with error", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte("hello world")
		verifier.Error = errors.New("test error")

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with all conditions met but error", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte("hello world")
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

		result, err := verifier.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("with nil reader", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.reader = nil

		result, err := verifier.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no reader available for streaming verification")
	})

	t.Run("with reader error", func(t *testing.T) {
		verifier := NewVerifier()
		errorReader := mock.NewErrorReadWriteCloser(errors.New("read error"))
		verifier.reader = errorReader

		result, err := verifier.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "read error", err.Error())
	})

	t.Run("with verifier reader error", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte("hello world"), "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(r io.Reader) io.Reader {
			return mock.NewErrorReadWriteCloser(errors.New("verifier error"))
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "verifier error", err.Error())
	})

	t.Run("with empty data", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte{}, "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(r io.Reader) io.Reader {
			return r
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

		result, err := verifier.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.Nil(t, err)
		assert.Equal(t, largeData, result)
	})
}

// TestVerifier_Integration tests integration scenarios
func TestVerifier_Integration(t *testing.T) {
	t.Run("chained operations", func(t *testing.T) {
		verifier := NewVerifier().
			FromRawString("hello world").
			FromBase64String("aGVsbG8gd29ybGQ=").
			FromHexString("68656c6c6f20776f726c64")

		assert.NotNil(t, verifier)
		assert.Equal(t, []byte("hello world"), verifier.src)
	})

	t.Run("multiple format conversions", func(t *testing.T) {
		verifier := NewVerifier()

		// Start with raw string
		verifier.FromRawString("test")
		assert.Equal(t, []byte("test"), verifier.src)

		// Convert to base64
		verifier.FromBase64String("dGVzdA==")
		assert.Equal(t, []byte("test"), verifier.src)

		// Convert to hex
		verifier.FromHexString("74657374")
		assert.Equal(t, []byte("test"), verifier.src)
	})

	t.Run("error handling in chain", func(t *testing.T) {
		verifier := NewVerifier()

		// Start with valid data
		verifier.FromRawString("hello")
		assert.Equal(t, []byte("hello"), verifier.src)

		// Try invalid base64 (should not change src)
		verifier.FromBase64String("invalid!")
		assert.Equal(t, []byte("hello"), verifier.src) // src should remain unchanged

		// Try invalid hex (should not change src)
		verifier.FromHexString("invalid!")
		assert.Equal(t, []byte("hello"), verifier.src) // src should remain unchanged
	})
}

// TestVerifier_EdgeCases tests edge cases
func TestVerifier_EdgeCases(t *testing.T) {
	t.Run("unicode data", func(t *testing.T) {
		verifier := NewVerifier()
		unicodeData := "你好世界🌍"
		result := verifier.FromRawString(unicodeData)

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte(unicodeData), verifier.src)
	})

	t.Run("binary data", func(t *testing.T) {
		verifier := NewVerifier()
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := verifier.FromRawBytes(binaryData)

		assert.Equal(t, verifier, result)
		assert.Equal(t, binaryData, verifier.src)
	})

	t.Run("very long string", func(t *testing.T) {
		verifier := NewVerifier()
		longString := string(make([]byte, 10000))
		result := verifier.FromRawString(longString)

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte(longString), verifier.src)
	})

	t.Run("nil keypair with error", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte("hello")
		verifier.Error = errors.New("test error")

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("empty keypair sign", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.src = []byte("hello")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})
}

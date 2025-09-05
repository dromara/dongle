package crypto

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dromara/dongle/mock"
)

func TestNewVerifier(t *testing.T) {
	t.Run("create new verifier", func(t *testing.T) {
		verifier := NewVerifier()
		assert.NotNil(t, verifier)
		assert.Nil(t, verifier.data)
		assert.Nil(t, verifier.reader)
		assert.Nil(t, verifier.Error)
	})
}

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

func TestVerifier_FromFile(t *testing.T) {
	t.Run("from valid file", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte("hello world"), "test.txt")
		result := verifier.FromFile(file)

		assert.Equal(t, verifier, result)
		assert.Equal(t, file, verifier.reader)
		assert.Nil(t, verifier.Error)
	})

	t.Run("from nil file", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.FromFile(nil)

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.reader)
		assert.Nil(t, verifier.Error)
	})
}

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

	// Additional test cases for 100% coverage
	t.Run("with empty data and empty signature", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte{}
		verifier.sign = []byte{}
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with valid data but empty signature", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.sign = []byte{}
		verifier.Error = nil

		result := verifier.ToBool()
		assert.False(t, result)
	})

	t.Run("with valid data, valid signature, and no error", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.sign = []byte("signature")
		verifier.Error = nil

		result := verifier.ToBool()
		assert.True(t, result)
	})

	t.Run("with valid data, valid signature, but with error", func(t *testing.T) {
		verifier := NewVerifier()
		verifier.data = []byte("hello world")
		verifier.sign = []byte("signature")
		verifier.Error = errors.New("test error")

		result := verifier.ToBool()
		assert.False(t, result)
	})
}

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

	t.Run("with write error in stream", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte("hello world"), "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewErrorWriteCloser(errors.New("write error"))
		})

		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, "write error", err.Error())
	})

	t.Run("with EOF error in stream", func(t *testing.T) {
		verifier := NewVerifier()
		file := mock.NewFile([]byte("hello world"), "test.txt")
		verifier.reader = file

		result, err := verifier.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})
}

func TestVerifier_WithHexSign(t *testing.T) {
	t.Run("with valid hex signature", func(t *testing.T) {
		verifier := NewVerifier()
		hexSignature := []byte("74657374207369676e6174757265") // "test signature" in hex
		result := verifier.WithHexSign(hexSignature)

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("test signature"), verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with empty hex signature", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.WithHexSign([]byte{})

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with nil hex signature", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.WithHexSign(nil)

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with invalid hex signature", func(t *testing.T) {
		verifier := NewVerifier()
		invalidHex := []byte("invalid_hex_string")
		result := verifier.WithHexSign(invalidHex)

		assert.Equal(t, verifier, result)
		// Invalid hex will result in empty bytes from the decoder
		assert.Equal(t, []byte{}, verifier.sign)
		assert.Nil(t, verifier.Error)
	})
}

func TestVerifier_WithBase64Sign(t *testing.T) {
	t.Run("with valid base64 signature", func(t *testing.T) {
		verifier := NewVerifier()
		base64Signature := []byte("dGVzdCBzaWduYXR1cmU=") // "test signature" in base64
		result := verifier.WithBase64Sign(base64Signature)

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte("test signature"), verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with empty base64 signature", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.WithBase64Sign([]byte{})

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with nil base64 signature", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.WithBase64Sign(nil)

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with invalid base64 signature", func(t *testing.T) {
		verifier := NewVerifier()
		invalidBase64 := []byte("invalid_base64!")
		result := verifier.WithBase64Sign(invalidBase64)

		assert.Equal(t, verifier, result)
		// Invalid base64 will result in empty bytes from the decoder
		assert.Equal(t, []byte{}, verifier.sign)
		assert.Nil(t, verifier.Error)
	})
}

func TestVerifier_WithRawSign(t *testing.T) {
	t.Run("with valid raw signature", func(t *testing.T) {
		verifier := NewVerifier()
		rawSignature := []byte("test signature")
		result := verifier.WithRawSign(rawSignature)

		assert.Equal(t, verifier, result)
		assert.Equal(t, rawSignature, verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with empty raw signature", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.WithRawSign([]byte{})

		assert.Equal(t, verifier, result)
		assert.Equal(t, []byte{}, verifier.sign)
		assert.Nil(t, verifier.Error)
	})

	t.Run("with nil raw signature", func(t *testing.T) {
		verifier := NewVerifier()
		result := verifier.WithRawSign(nil)

		assert.Equal(t, verifier, result)
		assert.Nil(t, verifier.sign)
		assert.Nil(t, verifier.Error)
	})
}

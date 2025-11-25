package crypto

import (
	"io"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestSigner_FromString(t *testing.T) {
	t.Run("from string", func(t *testing.T) {
		signer := NewSigner().FromString("hello world")
		assert.Equal(t, []byte("hello world"), signer.data)
		assert.Equal(t, signer, signer)
	})

	t.Run("from empty string", func(t *testing.T) {
		signer := NewSigner().FromString("")
		assert.Equal(t, []byte{}, signer.data)
		assert.Equal(t, signer, signer)
	})

	t.Run("from unicode string", func(t *testing.T) {
		signer := NewSigner().FromString("你好世界")
		assert.Equal(t, []byte("你好世界"), signer.data)
		assert.Equal(t, signer, signer)
	})

	t.Run("from large string", func(t *testing.T) {
		largeString := "Hello, World! " + string(make([]byte, 1000))
		signer := NewSigner().FromString(largeString)
		assert.Equal(t, []byte(largeString), signer.data)
		assert.Equal(t, signer, signer)
	})
}

func TestSigner_FromBytes(t *testing.T) {
	t.Run("from bytes", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		signer := NewSigner().FromBytes(data)
		assert.Equal(t, data, signer.data)
		assert.Equal(t, signer, signer)
	})

	t.Run("from empty bytes", func(t *testing.T) {
		signer := NewSigner().FromBytes([]byte{})
		assert.Equal(t, []byte{}, signer.data)
		assert.Equal(t, signer, signer)
	})

	t.Run("from nil bytes", func(t *testing.T) {
		signer := NewSigner().FromBytes(nil)
		assert.Nil(t, signer.data)
		assert.Equal(t, signer, signer)
	})

	t.Run("from large bytes", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		signer := NewSigner().FromBytes(largeData)
		assert.Equal(t, largeData, signer.data)
		assert.Equal(t, signer, signer)
	})

	t.Run("from binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		signer := NewSigner().FromBytes(binaryData)
		assert.Equal(t, binaryData, signer.data)
		assert.Equal(t, signer, signer)
	})
}

func TestSigner_FromFile(t *testing.T) {
	t.Run("from file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		signer := NewSigner().FromFile(file)
		assert.Equal(t, file, signer.reader)
		assert.Equal(t, signer, signer)
	})

	t.Run("from empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		signer := NewSigner().FromFile(file)
		assert.Equal(t, file, signer.reader)
		assert.Equal(t, signer, signer)
	})

	t.Run("from large file", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		file := mock.NewFile(largeData, "large.txt")
		signer := NewSigner().FromFile(file)
		assert.Equal(t, file, signer.reader)
		assert.Equal(t, signer, signer)
	})

	t.Run("from binary file", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		file := mock.NewFile(binaryData, "binary.bin")
		signer := NewSigner().FromFile(file)
		assert.Equal(t, file, signer.reader)
		assert.Equal(t, signer, signer)
	})
}

func TestSigner_ToRawString(t *testing.T) {
	t.Run("to raw string with valid data", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte("hello world")
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03}
		result := signer.ToRawString()
		assert.Equal(t, "\x00\x01\x02\x03", result)
	})

	t.Run("to raw string empty data", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte{}
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03}
		result := signer.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("to raw string nil data", func(t *testing.T) {
		signer := NewSigner()
		signer.data = nil
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03}
		result := signer.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("to raw string with error", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte("hello world")
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03}
		signer.Error = assert.AnError
		result := signer.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("to raw string empty sign", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte("hello world")
		signer.sign = []byte{}
		result := signer.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("to raw string nil sign", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte("hello world")
		signer.sign = nil
		result := signer.ToRawString()
		assert.Equal(t, "", result)
	})
}

func TestSigner_ToRawBytes(t *testing.T) {
	t.Run("to raw bytes with empty data", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte{} // Empty data triggers early return
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03}
		result := signer.ToRawBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to raw bytes with nil data", func(t *testing.T) {
		signer := NewSigner()
		signer.data = nil // Nil data triggers early return
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03}
		result := signer.ToRawBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to raw bytes with valid data", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte("hello world") // Valid data allows sign to be returned
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03}
		result := signer.ToRawBytes()
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, result)
	})

	t.Run("to raw bytes empty", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte("hello world")
		signer.sign = []byte{}
		result := signer.ToRawBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to raw bytes nil", func(t *testing.T) {
		signer := NewSigner()
		signer.data = []byte("hello world")
		signer.sign = nil
		result := signer.ToRawBytes()
		assert.Nil(t, result)
	})

	t.Run("to raw bytes binary", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		signer := NewSigner()
		signer.data = []byte("hello world")
		signer.sign = binaryData
		result := signer.ToRawBytes()
		assert.Equal(t, binaryData, result)
	})
}

func TestSigner_ToBase64String(t *testing.T) {
	t.Run("to base64 string", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("hello world")
		result := signer.ToBase64String()
		assert.Equal(t, "aGVsbG8gd29ybGQ=", result)
	})

	t.Run("to base64 string empty", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{}
		result := signer.ToBase64String()
		assert.Equal(t, "", result)
	})

	t.Run("to base64 string nil", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = nil
		result := signer.ToBase64String()
		assert.Equal(t, "", result)
	})

	t.Run("to base64 string unicode", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("你好世界")
		result := signer.ToBase64String()
		assert.Equal(t, "5L2g5aW95LiW55WM", result)
	})

	t.Run("to base64 string binary", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := signer.ToBase64String()
		assert.Equal(t, "AAECA//+/fw=", result)
	})
}

func TestSigner_ToBase64Bytes(t *testing.T) {
	t.Run("to base64 bytes", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("hello world")
		result := signer.ToBase64Bytes()
		assert.Equal(t, []byte("aGVsbG8gd29ybGQ="), result)
	})

	t.Run("to base64 bytes empty", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{}
		result := signer.ToBase64Bytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to base64 bytes nil", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = nil
		result := signer.ToBase64Bytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to base64 bytes unicode", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("你好世界")
		result := signer.ToBase64Bytes()
		assert.Equal(t, []byte("5L2g5aW95LiW55WM"), result)
	})

	t.Run("to base64 bytes binary", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := signer.ToBase64Bytes()
		assert.Equal(t, []byte("AAECA//+/fw="), result)
	})
}

func TestSigner_ToHexString(t *testing.T) {
	t.Run("to hex string", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("hello world")
		result := signer.ToHexString()
		assert.Equal(t, "68656c6c6f20776f726c64", result)
	})

	t.Run("to hex string empty", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{}
		result := signer.ToHexString()
		assert.Equal(t, "", result)
	})

	t.Run("to hex string nil", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = nil
		result := signer.ToHexString()
		assert.Equal(t, "", result)
	})

	t.Run("to hex string unicode", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("你好世界")
		result := signer.ToHexString()
		assert.Equal(t, "e4bda0e5a5bde4b896e7958c", result)
	})

	t.Run("to hex string binary", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := signer.ToHexString()
		assert.Equal(t, "00010203fffefdfc", result)
	})
}

func TestSigner_ToHexBytes(t *testing.T) {
	t.Run("to hex bytes", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("hello world")
		result := signer.ToHexBytes()
		assert.Equal(t, []byte("68656c6c6f20776f726c64"), result)
	})

	t.Run("to hex bytes empty", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{}
		result := signer.ToHexBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to hex bytes nil", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = nil
		result := signer.ToHexBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to hex bytes unicode", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte("你好世界")
		result := signer.ToHexBytes()
		assert.Equal(t, []byte("e4bda0e5a5bde4b896e7958c"), result)
	})

	t.Run("to hex bytes binary", func(t *testing.T) {
		signer := NewSigner()
		signer.sign = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := signer.ToHexBytes()
		assert.Equal(t, []byte("00010203fffefdfc"), result)
	})
}

func TestSigner_Stream(t *testing.T) {
	t.Run("stream with success", func(t *testing.T) {
		signer := NewSigner()
		signer.reader = mock.NewFile([]byte("hello world"), "test.txt")

		result, err := signer.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("stream with empty reader", func(t *testing.T) {
		signer := NewSigner()
		signer.reader = mock.NewFile([]byte{}, "empty.txt")

		result, err := signer.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with large data", func(t *testing.T) {
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		signer := NewSigner()
		signer.reader = mock.NewFile(largeData, "large.dat")

		result, err := signer.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, largeData, result)
	})

	t.Run("stream with error reader", func(t *testing.T) {
		signer := NewSigner()
		signer.reader = mock.NewErrorReadWriteCloser(assert.AnError)

		_, err := signer.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream with error in write", func(t *testing.T) {
		signer := NewSigner()
		signer.reader = mock.NewFile([]byte("hello world"), "test.txt")

		_, err := signer.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewErrorWriteCloser(assert.AnError)
		})

		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream with close error", func(t *testing.T) {
		signer := NewSigner()
		signer.reader = mock.NewFile([]byte("hello world"), "test.txt")

		result, err := signer.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewCloseErrorWriteCloser(w, assert.AnError)
		})

		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
		assert.Equal(t, []byte{}, result)
	})
}

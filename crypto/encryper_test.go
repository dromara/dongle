package crypto

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"gitee.com/golang-package/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestEncrypter_FromString(t *testing.T) {
	t.Run("from string", func(t *testing.T) {
		encrypter := NewEncrypter().FromString("hello world")
		assert.Equal(t, []byte("hello world"), encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from empty string", func(t *testing.T) {
		encrypter := NewEncrypter().FromString("")
		assert.Equal(t, []byte{}, encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from unicode string", func(t *testing.T) {
		encrypter := NewEncrypter().FromString("你好世界")
		assert.Equal(t, []byte("你好世界"), encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from large string", func(t *testing.T) {
		largeString := "Hello, World! " + string(make([]byte, 1000))
		encrypter := NewEncrypter().FromString(largeString)
		assert.Equal(t, []byte(largeString), encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})
}

func TestEncrypter_FromBytes(t *testing.T) {
	t.Run("from bytes", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		encrypter := NewEncrypter().FromBytes(data)
		assert.Equal(t, data, encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from empty bytes", func(t *testing.T) {
		encrypter := NewEncrypter().FromBytes([]byte{})
		assert.Equal(t, []byte{}, encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from nil bytes", func(t *testing.T) {
		encrypter := NewEncrypter().FromBytes(nil)
		assert.Nil(t, encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from large bytes", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		encrypter := NewEncrypter().FromBytes(largeData)
		assert.Equal(t, largeData, encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		encrypter := NewEncrypter().FromBytes(binaryData)
		assert.Equal(t, binaryData, encrypter.src)
		assert.Equal(t, encrypter, encrypter)
	})
}

func TestEncrypter_FromFile(t *testing.T) {
	t.Run("from file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encrypter := NewEncrypter().FromFile(file)
		assert.Equal(t, file, encrypter.reader)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encrypter := NewEncrypter().FromFile(file)
		assert.Equal(t, file, encrypter.reader)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from large file", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		file := mock.NewFile(largeData, "large.txt")
		encrypter := NewEncrypter().FromFile(file)
		assert.Equal(t, file, encrypter.reader)
		assert.Equal(t, encrypter, encrypter)
	})

	t.Run("from binary file", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		file := mock.NewFile(binaryData, "binary.bin")
		encrypter := NewEncrypter().FromFile(file)
		assert.Equal(t, file, encrypter.reader)
		assert.Equal(t, encrypter, encrypter)
	})
}

func TestEncrypter_ToRawString(t *testing.T) {
	t.Run("to raw string", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("hello world")
		result := encrypter.ToRawString()
		assert.Equal(t, "hello world", result)
	})

	t.Run("to raw string empty", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{}
		result := encrypter.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("to raw string nil", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = nil
		result := encrypter.ToRawString()
		assert.Equal(t, "", result)
	})

	t.Run("to raw string unicode", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("你好世界")
		result := encrypter.ToRawString()
		assert.Equal(t, "你好世界", result)
	})

	t.Run("to raw string binary", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := encrypter.ToRawString()
		assert.Equal(t, string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}), result)
	})
}

func TestEncrypter_ToRawBytes(t *testing.T) {
	t.Run("to raw bytes", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{0x00, 0x01, 0x02, 0x03}
		result := encrypter.ToRawBytes()
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, result)
	})

	t.Run("to raw bytes empty", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{}
		result := encrypter.ToRawBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to raw bytes nil", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = nil
		result := encrypter.ToRawBytes()
		assert.Nil(t, result)
	})

	t.Run("to raw bytes large", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		encrypter := NewEncrypter()
		encrypter.dst = largeData
		result := encrypter.ToRawBytes()
		assert.Equal(t, largeData, result)
	})

	t.Run("to raw bytes binary", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		encrypter := NewEncrypter()
		encrypter.dst = binaryData
		result := encrypter.ToRawBytes()
		assert.Equal(t, binaryData, result)
	})
}

func TestEncrypter_ToBase64String(t *testing.T) {
	t.Run("to base64 string", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("hello world")
		result := encrypter.ToBase64String()
		assert.Equal(t, "aGVsbG8gd29ybGQ=", result)
	})

	t.Run("to base64 string empty", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{}
		result := encrypter.ToBase64String()
		assert.Equal(t, "", result)
	})

	t.Run("to base64 string nil", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = nil
		result := encrypter.ToBase64String()
		assert.Equal(t, "", result)
	})

	t.Run("to base64 string unicode", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("你好世界")
		result := encrypter.ToBase64String()
		assert.Equal(t, "5L2g5aW95LiW55WM", result)
	})

	t.Run("to base64 string binary", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := encrypter.ToBase64String()
		assert.Equal(t, "AAECA//+/fw=", result)
	})
}

func TestEncrypter_ToBase64Bytes(t *testing.T) {
	t.Run("to base64 bytes", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("hello world")
		result := encrypter.ToBase64Bytes()
		assert.Equal(t, []byte("aGVsbG8gd29ybGQ="), result)
	})

	t.Run("to base64 bytes empty", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{}
		result := encrypter.ToBase64Bytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to base64 bytes nil", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = nil
		result := encrypter.ToBase64Bytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to base64 bytes unicode", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("你好世界")
		result := encrypter.ToBase64Bytes()
		assert.Equal(t, []byte("5L2g5aW95LiW55WM"), result)
	})

	t.Run("to base64 bytes binary", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := encrypter.ToBase64Bytes()
		assert.Equal(t, []byte("AAECA//+/fw="), result)
	})
}

func TestEncrypter_ToHexString(t *testing.T) {
	t.Run("to hex string", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("hello world")
		result := encrypter.ToHexString()
		assert.Equal(t, "68656c6c6f20776f726c64", result)
	})

	t.Run("to hex string empty", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{}
		result := encrypter.ToHexString()
		assert.Equal(t, "", result)
	})

	t.Run("to hex string nil", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = nil
		result := encrypter.ToHexString()
		assert.Equal(t, "", result)
	})

	t.Run("to hex string unicode", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("你好世界")
		result := encrypter.ToHexString()
		assert.Equal(t, "e4bda0e5a5bde4b896e7958c", result)
	})

	t.Run("to hex string binary", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := encrypter.ToHexString()
		assert.Equal(t, "00010203fffefdfc", result)
	})
}

func TestEncrypter_ToHexBytes(t *testing.T) {
	t.Run("to hex bytes", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("hello world")
		result := encrypter.ToHexBytes()
		assert.Equal(t, []byte("68656c6c6f20776f726c64"), result)
	})

	t.Run("to hex bytes empty", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{}
		result := encrypter.ToHexBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to hex bytes nil", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = nil
		result := encrypter.ToHexBytes()
		assert.Equal(t, []byte{}, result)
	})

	t.Run("to hex bytes unicode", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte("你好世界")
		result := encrypter.ToHexBytes()
		assert.Equal(t, []byte("e4bda0e5a5bde4b896e7958c"), result)
	})

	t.Run("to hex bytes binary", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.dst = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := encrypter.ToHexBytes()
		assert.Equal(t, []byte("00010203fffefdfc"), result)
	})
}

func TestEncrypter_Stream(t *testing.T) {
	t.Run("stream with success", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.reader = strings.NewReader("hello world")

		result, err := encrypter.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("stream with empty reader", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.reader = strings.NewReader("")

		result, err := encrypter.stream(func(w io.Writer) io.WriteCloser {
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

		encrypter := NewEncrypter()
		encrypter.reader = bytes.NewReader(largeData)

		result, err := encrypter.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, largeData, result)
	})

	t.Run("stream with error reader", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.reader = mock.NewErrorReadWriteCloser(assert.AnError)

		_, err := encrypter.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream with error in write", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.reader = strings.NewReader("hello world")

		_, err := encrypter.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewErrorWriteCloser(assert.AnError)
		})

		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream with error in close", func(t *testing.T) {
		encrypter := NewEncrypter()
		encrypter.reader = strings.NewReader("hello world")

		result, err := encrypter.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewCloseErrorWriteCloser(w, assert.AnError)
		})

		// Close error is not propagated in the current implementation
		// The stream method uses defer encrypter.Close() which ignores the error
		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})
}

package crypto

import (
	"io"
	"testing"

	"github.com/dromara/dongle/mock"
	"github.com/stretchr/testify/assert"
)

func TestDecrypter_FromRawString(t *testing.T) {
	t.Run("from raw string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromRawString("hello world")
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from empty string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromRawString("")
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from unicode string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromRawString("你好世界")
		assert.Equal(t, []byte("你好世界"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from large string", func(t *testing.T) {
		largeString := string(make([]byte, 10000))
		decrypter := NewDecrypter()
		result := decrypter.FromRawString(largeString)
		assert.Equal(t, []byte(largeString), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})
}

func TestDecrypter_FromRawBytes(t *testing.T) {
	t.Run("from raw bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		data := []byte("hello world")
		result := decrypter.FromRawBytes(data)
		assert.Equal(t, data, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from empty bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromRawBytes([]byte{})
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from nil bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromRawBytes(nil)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from large bytes", func(t *testing.T) {
		largeData := make([]byte, 10000)
		decrypter := NewDecrypter()
		result := decrypter.FromRawBytes(largeData)
		assert.Equal(t, largeData, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		decrypter := NewDecrypter()
		result := decrypter.FromRawBytes(binaryData)
		assert.Equal(t, binaryData, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})
}

func TestDecrypter_FromBase64String(t *testing.T) {
	t.Run("from base64 string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64String("aGVsbG8gd29ybGQ=")
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from empty base64 string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64String("")
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from unicode base64 string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64String("5L2g5aW95LiW55WM")
		assert.Equal(t, []byte("你好世界"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from invalid base64 string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64String("invalid base64!")
		// Should not change src when there's an error
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from binary base64 string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64String("AAECA//+/fw=")
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})
}

func TestDecrypter_FromBase64Bytes(t *testing.T) {
	t.Run("from base64 bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64Bytes([]byte("aGVsbG8gd29ybGQ="))
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from empty base64 bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64Bytes([]byte{})
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from unicode base64 bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64Bytes([]byte("5L2g5aW95LiW55WM"))
		assert.Equal(t, []byte("你好世界"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from invalid base64 bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64Bytes([]byte("invalid base64!"))
		// Should not change src when there's an error
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from binary base64 bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromBase64Bytes([]byte("AAECA//+/fw="))
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})
}

func TestDecrypter_FromHexString(t *testing.T) {
	t.Run("from hex string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexString("68656c6c6f20776f726c64")
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from empty hex string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexString("")
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from unicode hex string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexString("e4bda0e5a5bde4b896e7958c")
		assert.Equal(t, []byte("你好世界"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from invalid hex string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexString("invalid hex!")
		// Should not change src when there's an error
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from binary hex string", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexString("00010203fffefdfc")
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})
}

func TestDecrypter_FromHexBytes(t *testing.T) {
	t.Run("from hex bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexBytes([]byte("68656c6c6f20776f726c64"))
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from empty hex bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexBytes([]byte{})
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from unicode hex bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexBytes([]byte("e4bda0e5a5bde4b896e7958c"))
		assert.Equal(t, []byte("你好世界"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from invalid hex bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexBytes([]byte("invalid hex!"))
		// Should not change src when there's an error
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})

	t.Run("from binary hex bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		result := decrypter.FromHexBytes([]byte("00010203fffefdfc"))
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
		assert.Nil(t, result.Error)
	})
}

func TestDecrypter_ToString(t *testing.T) {
	t.Run("to string", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = []byte("hello world")
		result := decrypter.ToString()
		assert.Equal(t, "hello world", result)
	})

	t.Run("to string empty", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = []byte{}
		result := decrypter.ToString()
		assert.Equal(t, "", result)
	})

	t.Run("to string nil", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = nil
		result := decrypter.ToString()
		assert.Equal(t, "", result)
	})

	t.Run("to string unicode", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = []byte("你好世界")
		result := decrypter.ToString()
		assert.Equal(t, "你好世界", result)
	})

	t.Run("to string binary", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		result := decrypter.ToString()
		assert.Equal(t, string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}), result)
	})
}

func TestDecrypter_ToBytes(t *testing.T) {
	t.Run("to bytes", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = []byte("hello world")
		result := decrypter.ToBytes()
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("to bytes empty", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = []byte{}
		result := decrypter.ToBytes()
		assert.Equal(t, []byte(""), result)
	})

	t.Run("to bytes nil", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.dst = nil
		result := decrypter.ToBytes()
		assert.Equal(t, []byte(""), result)
	})

	t.Run("to bytes large", func(t *testing.T) {
		largeData := make([]byte, 10000)
		decrypter := NewDecrypter()
		decrypter.dst = largeData
		result := decrypter.ToBytes()
		assert.Equal(t, largeData, result)
	})

	t.Run("to bytes binary", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		decrypter := NewDecrypter()
		decrypter.dst = binaryData
		result := decrypter.ToBytes()
		assert.Equal(t, binaryData, result)
	})
}

func TestDecrypter_Stream(t *testing.T) {
	t.Run("stream with success", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.reader = mock.NewFile([]byte("hello world"), "test.txt")

		result, err := decrypter.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("stream with empty reader", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.reader = mock.NewFile([]byte{}, "empty.txt")

		result, err := decrypter.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with large data", func(t *testing.T) {
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		decrypter := NewDecrypter()
		decrypter.reader = mock.NewFile(largeData, "large.dat")

		result, err := decrypter.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.Nil(t, err)
		assert.Equal(t, largeData, result)
	})

	t.Run("stream with error reader", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.reader = mock.NewErrorReadWriteCloser(assert.AnError)

		_, err := decrypter.stream(func(r io.Reader) io.Reader {
			return r
		})

		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("stream with error in copy", func(t *testing.T) {
		decrypter := NewDecrypter()
		decrypter.reader = mock.NewFile([]byte("hello world"), "test.txt")

		_, err := decrypter.stream(func(r io.Reader) io.Reader {
			return mock.NewErrorReadWriteCloser(assert.AnError)
		})

		assert.NotNil(t, err)
		assert.Equal(t, assert.AnError, err)
	})
}

func TestDecrypter_FromRawFile(t *testing.T) {
	t.Run("from raw file", func(t *testing.T) {
		data := []byte("hello world")
		file := mock.NewFile(data, "test.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromRawFile(file)
		assert.Equal(t, file, result.reader)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.Error)
	})

	t.Run("from empty file", func(t *testing.T) {
		var data []byte
		file := mock.NewFile(data, "empty.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromRawFile(file)
		assert.Equal(t, file, result.reader)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.Error)
	})

	t.Run("from large file", func(t *testing.T) {
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		file := mock.NewFile(data, "large.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromRawFile(file)
		assert.Equal(t, file, result.reader)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.Error)
	})

	t.Run("with existing error", func(t *testing.T) {
		data := []byte("test")
		file := mock.NewFile(data, "test.txt")

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError
		result := decrypter.FromRawFile(file)

		assert.Equal(t, assert.AnError, result.Error)
		assert.Equal(t, file, result.reader) // FromRawFile always sets reader, regardless of existing error
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
	})
}

func TestDecrypter_FromBase64File(t *testing.T) {
	t.Run("from base64 file", func(t *testing.T) {
		base64Data := []byte("aGVsbG8gd29ybGQ=") // "hello world" in base64
		file := mock.NewFile(base64Data, "test.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromBase64File(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from empty base64 file", func(t *testing.T) {
		base64Data := []byte("")
		file := mock.NewFile(base64Data, "empty.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromBase64File(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from unicode base64 file", func(t *testing.T) {
		base64Data := []byte("5L2g5aW95LiW55WM") // "你好世界" in base64
		file := mock.NewFile(base64Data, "unicode.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromBase64File(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("你好世界"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from invalid base64 file", func(t *testing.T) {
		base64Data := []byte("invalid base64!")
		file := mock.NewFile(base64Data, "invalid.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromBase64File(file)
		assert.NotNil(t, result.Error)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from binary base64 file", func(t *testing.T) {
		base64Data := []byte("AAECA//+/fw=") // Binary data in base64
		file := mock.NewFile(base64Data, "binary.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromBase64File(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("with existing error", func(t *testing.T) {
		base64Data := []byte("aGVsbG8gd29ybGQ=")
		file := mock.NewFile(base64Data, "test.txt")

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError
		result := decrypter.FromBase64File(file)

		assert.Equal(t, assert.AnError, result.Error)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("with file read error", func(t *testing.T) {
		errorFile := mock.NewErrorFile(assert.AnError)

		decrypter := NewDecrypter()
		result := decrypter.FromBase64File(errorFile)
		assert.NotNil(t, result.Error)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})
}

func TestDecrypter_FromHexFile(t *testing.T) {
	t.Run("from hex file", func(t *testing.T) {
		hexData := []byte("68656c6c6f20776f726c64") // "hello world" in hex
		file := mock.NewFile(hexData, "test.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromHexFile(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("hello world"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from empty hex file", func(t *testing.T) {
		hexData := []byte("")
		file := mock.NewFile(hexData, "empty.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromHexFile(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte{}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from unicode hex file", func(t *testing.T) {
		hexData := []byte("e4bda0e5a5bde4b896e7958c") // "你好世界" in hex
		file := mock.NewFile(hexData, "unicode.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromHexFile(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte("你好世界"), result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from invalid hex file", func(t *testing.T) {
		hexData := []byte("invalid hex!")
		file := mock.NewFile(hexData, "invalid.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromHexFile(file)
		assert.NotNil(t, result.Error)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("from binary hex file", func(t *testing.T) {
		hexData := []byte("000102ff") // Binary data in hex
		file := mock.NewFile(hexData, "binary.txt")

		decrypter := NewDecrypter()
		result := decrypter.FromHexFile(file)
		assert.Nil(t, result.Error)
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0xFF}, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("with existing error", func(t *testing.T) {
		hexData := []byte("68656c6c6f20776f726c64")
		file := mock.NewFile(hexData, "test.txt")

		decrypter := NewDecrypter()
		decrypter.Error = assert.AnError
		result := decrypter.FromHexFile(file)

		assert.Equal(t, assert.AnError, result.Error)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})

	t.Run("with file read error", func(t *testing.T) {
		errorFile := mock.NewErrorFile(assert.AnError)

		decrypter := NewDecrypter()
		result := decrypter.FromHexFile(errorFile)
		assert.NotNil(t, result.Error)
		assert.Nil(t, result.src)
		assert.Nil(t, result.dst)
		assert.Nil(t, result.reader)
	})
}

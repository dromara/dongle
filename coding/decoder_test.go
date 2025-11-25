package coding

import (
	"errors"
	"io"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestDecoder_FromString(t *testing.T) {
	t.Run("from string", func(t *testing.T) {
		decoder := NewDecoder().FromString("hello world")
		assert.Equal(t, []byte("hello world"), decoder.src)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("")
		assert.Equal(t, []byte{}, decoder.src)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from unicode string", func(t *testing.T) {
		decoder := NewDecoder().FromString("你好世界")
		assert.Equal(t, []byte("你好世界"), decoder.src)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from large string", func(t *testing.T) {
		largeString := "Hello, World! " + string(make([]byte, 1000))
		decoder := NewDecoder().FromString(largeString)
		assert.Equal(t, []byte(largeString), decoder.src)
		assert.Equal(t, decoder, decoder)
	})
}

func TestDecoder_FromBytes(t *testing.T) {
	t.Run("from bytes", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		decoder := NewDecoder().FromBytes(data)
		assert.Equal(t, data, decoder.src)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{})
		assert.Equal(t, []byte{}, decoder.src)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil)
		assert.Nil(t, decoder.src)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from large bytes", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		decoder := NewDecoder().FromBytes(largeData)
		assert.Equal(t, largeData, decoder.src)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		decoder := NewDecoder().FromBytes(binaryData)
		assert.Equal(t, binaryData, decoder.src)
		assert.Equal(t, decoder, decoder)
	})
}

func TestDecoder_FromFile(t *testing.T) {
	t.Run("from file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		decoder := NewDecoder().FromFile(file)
		assert.Equal(t, file, decoder.reader)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file)
		assert.Equal(t, file, decoder.reader)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile)
		assert.Equal(t, errorFile, decoder.reader)
		assert.Equal(t, decoder, decoder)
	})

	t.Run("from large file", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		file := mock.NewFile(largeData, "large.txt")
		decoder := NewDecoder().FromFile(file)
		assert.Equal(t, file, decoder.reader)
		assert.Equal(t, decoder, decoder)
	})
}

func TestDecoder_ToString(t *testing.T) {
	t.Run("to string with data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte("hello world")
		result := decoder.ToString()
		assert.Equal(t, "hello world", result)
	})

	t.Run("to string with empty data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte{}
		result := decoder.ToString()
		assert.Equal(t, "", result)
	})

	t.Run("to string with nil data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = nil
		result := decoder.ToString()
		assert.Equal(t, "", result)
	})

	t.Run("to string with unicode data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte("你好世界")
		result := decoder.ToString()
		assert.Equal(t, "你好世界", result)
	})

	t.Run("to string with binary data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte{0x00, 0x01, 0x02, 0x03}
		result := decoder.ToString()
		assert.Equal(t, string([]byte{0x00, 0x01, 0x02, 0x03}), result)
	})
}

func TestDecoder_ToBytes(t *testing.T) {
	t.Run("to bytes with data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte("hello world")
		result := decoder.ToBytes()
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("to bytes with empty data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte{}
		result := decoder.ToBytes()
		assert.Equal(t, []byte(""), result)
	})

	t.Run("to bytes with nil data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = nil
		result := decoder.ToBytes()
		assert.Equal(t, []byte(""), result)
	})

	t.Run("to bytes with unicode data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte("你好世界")
		result := decoder.ToBytes()
		assert.Equal(t, []byte("你好世界"), result)
	})

	t.Run("to bytes with binary data", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.dst = []byte{0x00, 0x01, 0x02, 0x03}
		result := decoder.ToBytes()
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, result)
	})

	t.Run("to bytes with large data", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		decoder := NewDecoder()
		decoder.dst = largeData
		result := decoder.ToBytes()
		assert.Equal(t, largeData, result)
	})
}

func TestDecoder_stream(t *testing.T) {
	t.Run("success with data", func(t *testing.T) {
		data := []byte("hello decode stream")
		file := mock.NewFile(data, "d.txt")
		decoder := NewDecoder().FromFile(file)
		out, err := decoder.stream(func(r io.Reader) io.Reader {
			return r
		})
		assert.NoError(t, err)
		assert.Equal(t, data, out)
	})

	t.Run("empty reader returns empty", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		decoder := NewDecoder().FromFile(file)
		out, err := decoder.stream(func(r io.Reader) io.Reader { return r })
		assert.NoError(t, err)
		assert.Equal(t, []byte{}, out)
	})

	t.Run("decoder read error", func(t *testing.T) {
		readErr := errors.New("read error")
		errReader := mock.NewErrorReadWriteCloser(readErr)
		decoder := NewDecoder()
		decoder.reader = errReader
		out, err := decoder.stream(func(r io.Reader) io.Reader { return errReader })
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read error")
		assert.Equal(t, []byte{}, out)
	})
}

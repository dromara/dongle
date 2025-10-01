package coding

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dromara/dongle/mock"
)

func TestEncoder_FromString(t *testing.T) {
	t.Run("from string", func(t *testing.T) {
		encoder := NewEncoder().FromString("hello world")
		assert.Equal(t, []byte("hello world"), encoder.src)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("")
		assert.Equal(t, []byte{}, encoder.src)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from unicode string", func(t *testing.T) {
		encoder := NewEncoder().FromString("你好世界")
		assert.Equal(t, []byte("你好世界"), encoder.src)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from large string", func(t *testing.T) {
		largeString := "Hello, World! " + string(make([]byte, 1000))
		encoder := NewEncoder().FromString(largeString)
		assert.Equal(t, []byte(largeString), encoder.src)
		assert.Equal(t, encoder, encoder)
	})
}

func TestEncoder_FromBytes(t *testing.T) {
	t.Run("from bytes", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0x03}
		encoder := NewEncoder().FromBytes(data)
		assert.Equal(t, data, encoder.src)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{})
		assert.Equal(t, []byte{}, encoder.src)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil)
		assert.Nil(t, encoder.src)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from large bytes", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		encoder := NewEncoder().FromBytes(largeData)
		assert.Equal(t, largeData, encoder.src)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from binary data", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		encoder := NewEncoder().FromBytes(binaryData)
		assert.Equal(t, binaryData, encoder.src)
		assert.Equal(t, encoder, encoder)
	})
}

func TestEncoder_FromFile(t *testing.T) {
	t.Run("from file", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder().FromFile(file)
		assert.Equal(t, file, encoder.reader)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder().FromFile(file)
		assert.Equal(t, file, encoder.reader)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile)
		assert.Equal(t, errorFile, encoder.reader)
		assert.Equal(t, encoder, encoder)
	})

	t.Run("from large file", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		file := mock.NewFile(largeData, "large.txt")
		encoder := NewEncoder().FromFile(file)
		assert.Equal(t, file, encoder.reader)
		assert.Equal(t, encoder, encoder)
	})
}

func TestEncoder_ToString(t *testing.T) {
	t.Run("to string with data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte("hello world")
		result := encoder.ToString()
		assert.Equal(t, "hello world", result)
	})

	t.Run("to string with empty data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte{}
		result := encoder.ToString()
		assert.Equal(t, "", result)
	})

	t.Run("to string with nil data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = nil
		result := encoder.ToString()
		assert.Equal(t, "", result)
	})

	t.Run("to string with unicode data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte("你好世界")
		result := encoder.ToString()
		assert.Equal(t, "你好世界", result)
	})

	t.Run("to string with binary data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte{0x00, 0x01, 0x02, 0x03}
		result := encoder.ToString()
		assert.Equal(t, string([]byte{0x00, 0x01, 0x02, 0x03}), result)
	})
}

func TestEncoder_ToBytes(t *testing.T) {
	t.Run("to bytes with data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte("hello world")
		result := encoder.ToBytes()
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("to bytes with empty data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte{}
		result := encoder.ToBytes()
		assert.Equal(t, []byte(""), result)
	})

	t.Run("to bytes with nil data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = nil
		result := encoder.ToBytes()
		assert.Equal(t, []byte(""), result)
	})

	t.Run("to bytes with unicode data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte("你好世界")
		result := encoder.ToBytes()
		assert.Equal(t, []byte("你好世界"), result)
	})

	t.Run("to bytes with binary data", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.dst = []byte{0x00, 0x01, 0x02, 0x03}
		result := encoder.ToBytes()
		assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03}, result)
	})

	t.Run("to bytes with large data", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		encoder := NewEncoder()
		encoder.dst = largeData
		result := encoder.ToBytes()
		assert.Equal(t, largeData, result)
	})
}

func TestEncoder_stream(t *testing.T) {
	t.Run("stream with normal writer", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("stream with empty writer", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with error writer", func(t *testing.T) {
		errorWriter := mock.NewErrorWriteCloser(errors.New("write error"))
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return errorWriter
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write error")
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with large writer", func(t *testing.T) {
		largeData := make([]byte, 1000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		file := mock.NewFile(largeData, "large.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, largeData, result)
	})

	t.Run("stream with binary writer", func(t *testing.T) {
		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
		file := mock.NewFile(binaryData, "binary.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, binaryData, result)
	})

	t.Run("stream with transform function", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			// Simulate a transform that writes the same data
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte("hello world"), result)
	})

	t.Run("stream with error in transform function", func(t *testing.T) {
		file := mock.NewFile([]byte("hello world"), "test.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			// Return an error write closer
			return mock.NewErrorWriteCloser(errors.New("transform error"))
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transform error")
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with write error", func(t *testing.T) {
		// Test the encoder.Write error path
		file := mock.NewFile([]byte("test data"), "test.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			// Return a write closer that will fail on Write
			return mock.NewErrorWriteCloser(errors.New("write failed"))
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "write failed")
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with close error", func(t *testing.T) {
		// Test the encoder.Close error path
		file := mock.NewFile([]byte("test data"), "test.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			// Return a write closer that will fail on Close
			return mock.NewCloseErrorWriteCloser(w, errors.New("close failed"))
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "close failed")
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with single byte data", func(t *testing.T) {
		// Test with single byte to cover small data handling
		file := mock.NewFile([]byte{0x41}, "single.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, []byte{0x41}, result)
	})

	t.Run("stream with exact buffer size data", func(t *testing.T) {
		// Test with data that exactly matches buffer size
		const bufferSize = 64 * 1024
		exactData := make([]byte, bufferSize)
		for i := range exactData {
			exactData[i] = byte(i % 256)
		}

		file := mock.NewFile(exactData, "exact.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, exactData, result)
	})

	t.Run("stream with larger than buffer data", func(t *testing.T) {
		// Test with data larger than buffer size
		const largeSize = 128 * 1024 // 128KB
		largeData := make([]byte, largeSize)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		file := mock.NewFile(largeData, "large.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, largeData, result)
	})

	t.Run("stream with partial buffer data", func(t *testing.T) {
		// Test with data that requires partial buffer handling
		partialData := make([]byte, 100*1024) // 100KB
		for i := range partialData {
			partialData[i] = byte(i % 256)
		}

		file := mock.NewFile(partialData, "partial.txt")
		encoder := NewEncoder()
		encoder.reader = file

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return mock.NewWriteCloser(w)
		})

		assert.Nil(t, err)
		assert.Equal(t, partialData, result)
	})
}

func TestEncoder_Error(t *testing.T) {
	t.Run("stream with pipe error", func(t *testing.T) {
		errorWriter := mock.NewErrorReadWriteCloser(errors.New("copy error"))
		encoder := NewEncoder()
		encoder.reader = errorWriter

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return errorWriter
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "copy error")
		assert.Equal(t, []byte{}, result)
	})

	t.Run("stream with close error", func(t *testing.T) {
		closeErrorWriter := mock.NewErrorReadWriteCloser(errors.New("close error"))
		encoder := NewEncoder()
		encoder.reader = closeErrorWriter

		result, err := encoder.stream(func(w io.Writer) io.WriteCloser {
			return closeErrorWriter
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "close error")
		assert.Equal(t, []byte{}, result)
	})
}

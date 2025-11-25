package mock

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewFile(t *testing.T) {
	// Test NewFile with valid data
	data := []byte("test content")
	name := "test.txt"
	file := NewFile(data, name)

	assert.NotNil(t, file)
	assert.Equal(t, data, file.data)
	assert.Equal(t, name, file.name)
	assert.Equal(t, int64(0), file.pos)
	assert.False(t, file.closed)
}

func TestFile_Read(t *testing.T) {
	t.Run("read from open file", func(t *testing.T) {
		content := []byte("Hello, World!")
		file := NewFile(content, "test.txt")

		// Test reading with buffer smaller than content
		buf := make([]byte, 5)
		n, err := file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("Hello"), buf)
		assert.Equal(t, int64(5), file.pos)

		// Test reading remaining content
		buf2 := make([]byte, 10)
		n, err = file.Read(buf2)
		assert.NoError(t, err)
		assert.Equal(t, 8, n) // ", World!" has 8 characters
		assert.Equal(t, []byte(", World!"), buf2[:n])
		assert.Equal(t, int64(13), file.pos)

		// Test reading at EOF
		buf3 := make([]byte, 10)
		n, err = file.Read(buf3)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read from closed file", func(t *testing.T) {
		content := []byte("test content")
		file := NewFile(content, "test.txt")
		file.Close()

		buf := make([]byte, 10)
		n, err := file.Read(buf)
		assert.Equal(t, os.ErrClosed, err)
		assert.Equal(t, 0, n)
	})

	t.Run("read with empty buffer", func(t *testing.T) {
		content := []byte("test content")
		file := NewFile(content, "test.txt")

		buf := make([]byte, 0)
		n, err := file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, int64(0), file.pos)
	})

	t.Run("read from empty file", func(t *testing.T) {
		file := NewFile([]byte{}, "empty.txt")

		buf := make([]byte, 10)
		n, err := file.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

func TestFile_Close(t *testing.T) {
	file := NewFile([]byte("test"), "test.txt")

	// Test closing open file
	err := file.Close()
	assert.NoError(t, err)
	assert.True(t, file.closed)

	// Test closing already closed file
	err = file.Close()
	assert.NoError(t, err)
	assert.True(t, file.closed)
}

func TestFile_Write(t *testing.T) {
	t.Run("write to open file", func(t *testing.T) {
		file := NewFile([]byte{}, "test.txt")

		// Test writing data
		data := []byte("Hello, World!")
		n, err := file.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, data, file.data)
		assert.Equal(t, int64(len(data)), file.pos)

		// Test writing more data
		data2 := []byte(" More content")
		n, err = file.Write(data2)
		assert.NoError(t, err)
		assert.Equal(t, len(data2), n)
		assert.Equal(t, append(data, data2...), file.data)
		assert.Equal(t, int64(len(data)+len(data2)), file.pos)
	})

	t.Run("write to closed file", func(t *testing.T) {
		file := NewFile([]byte{}, "test.txt")
		file.Close()

		data := []byte("test")
		n, err := file.Write(data)
		assert.Equal(t, os.ErrClosed, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte{}, file.data)
	})

	t.Run("write to file with existing content", func(t *testing.T) {
		file := NewFile([]byte("Hello"), "test.txt")

		// Write at current position (beginning of file)
		data := []byte(", World!")
		n, err := file.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, []byte(", World!"), file.data)

		// Reset file and seek to beginning
		file = NewFile([]byte("Hello"), "test.txt")
		file.Seek(0, io.SeekStart)
		data2 := []byte("Hi")
		n, err = file.Write(data2)
		assert.NoError(t, err)
		assert.Equal(t, len(data2), n)
		assert.Equal(t, []byte("Hi"), file.data)
	})

	t.Run("write empty data", func(t *testing.T) {
		file := NewFile([]byte{}, "test.txt")

		var data []byte
		n, err := file.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, []byte{}, file.data)
		assert.Equal(t, int64(0), file.pos)
	})

	t.Run("write beyond current data length", func(t *testing.T) {
		file := NewFile([]byte("Hello"), "test.txt")

		// Seek beyond current data
		file.Seek(10, io.SeekStart)

		// Write data
		data := []byte("World")
		n, err := file.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)

		// Check that file was extended with zeros
		expected := make([]byte, 15)
		copy(expected, "Hello")
		copy(expected[10:], data)
		assert.Equal(t, expected, file.data)
	})
}

func TestFile_Stat(t *testing.T) {
	content := []byte("test content")
	name := "test.txt"
	file := NewFile(content, name)

	// Test Stat on open file
	fileInfo, err := file.Stat()
	assert.NoError(t, err)
	assert.NotNil(t, fileInfo)
	assert.Equal(t, name, fileInfo.Name())
	assert.Equal(t, int64(len(content)), fileInfo.Size())
	assert.False(t, fileInfo.IsDir())

	// Test fileInfo methods
	assert.Equal(t, os.FileMode(0444), fileInfo.Mode())
	assert.Equal(t, time.Time{}, fileInfo.ModTime())
	assert.Nil(t, fileInfo.Sys())

	// Test Stat on closed file (should still work)
	file.Close()
	fileInfo2, err := file.Stat()
	assert.NoError(t, err)
	assert.NotNil(t, fileInfo2)
}

func TestFile_ReadDir(t *testing.T) {
	file := NewFile([]byte("test"), "test.txt")

	// Test ReadDir on file (should return error)
	entries, err := file.ReadDir(10)
	assert.Error(t, err)
	assert.Equal(t, "not a directory", err.Error())
	assert.Nil(t, entries)

	// Test ReadDir on closed file (should still return same error)
	file.Close()
	entries2, err := file.ReadDir(10)
	assert.Error(t, err)
	assert.Equal(t, "not a directory", err.Error())
	assert.Nil(t, entries2)
}

func TestFile_Seek(t *testing.T) {
	content := []byte("Hello, World!")
	file := NewFile(content, "test.txt")

	t.Run("seek from start", func(t *testing.T) {
		pos, err := file.Seek(5, io.SeekStart)
		assert.NoError(t, err)
		assert.Equal(t, int64(5), pos)
		assert.Equal(t, int64(5), file.pos)

		// Read from new position
		buf := make([]byte, 3)
		n, err := file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 3, n)
		assert.Equal(t, []byte(", W"), buf)
	})

	t.Run("seek from current", func(t *testing.T) {
		file.pos = 0 // Reset position
		pos, err := file.Seek(2, io.SeekCurrent)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), pos)
		assert.Equal(t, int64(2), file.pos)
	})

	t.Run("seek from end", func(t *testing.T) {
		file.pos = 0 // Reset position
		pos, err := file.Seek(-3, io.SeekEnd)
		assert.NoError(t, err)
		assert.Equal(t, int64(10), pos) // len(content) - 3 = 13 - 3 = 10
		assert.Equal(t, int64(10), file.pos)

		// Read from new position
		buf := make([]byte, 3)
		n, err := file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 3, n)
		assert.Equal(t, []byte("ld!"), buf)
	})

	t.Run("seek with invalid whence", func(t *testing.T) {
		pos, err := file.Seek(0, 999)
		assert.Error(t, err)
		assert.Equal(t, "invalid whence", err.Error())
		assert.Equal(t, int64(0), pos)
	})

	t.Run("seek with negative position", func(t *testing.T) {
		pos, err := file.Seek(-1, io.SeekStart)
		assert.Error(t, err)
		assert.Equal(t, "negative position", err.Error())
		assert.Equal(t, int64(0), pos)
	})

	t.Run("seek on closed file", func(t *testing.T) {
		file.Close()
		pos, err := file.Seek(0, io.SeekStart)
		assert.Equal(t, os.ErrClosed, err)
		assert.Equal(t, int64(0), pos)
	})

	t.Run("seek to exact end", func(t *testing.T) {
		file2 := NewFile(content, "test2.txt")
		pos, err := file2.Seek(0, io.SeekEnd)
		assert.NoError(t, err)
		assert.Equal(t, int64(len(content)), pos)
		assert.Equal(t, int64(len(content)), file2.pos)
	})

	t.Run("seek beyond end", func(t *testing.T) {
		file3 := NewFile(content, "test3.txt")
		pos, err := file3.Seek(20, io.SeekStart)
		assert.NoError(t, err)
		assert.Equal(t, int64(20), pos)
		assert.Equal(t, int64(20), file3.pos)

		// Reading from beyond end should return EOF
		buf := make([]byte, 10)
		n, err := file3.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})
}

func TestNewErrorFile(t *testing.T) {
	customError := errors.New("custom error")
	errorFile := NewErrorFile(customError)

	assert.NotNil(t, errorFile)
	assert.Equal(t, customError, errorFile.err)
}

func TestErrorFile_Read(t *testing.T) {
	customError := errors.New("custom read error")
	errorFile := NewErrorFile(customError)

	buf := make([]byte, 10)
	n, err := errorFile.Read(buf)
	assert.Equal(t, customError, err)
	assert.Equal(t, 0, n)
}

func TestErrorFile_Close(t *testing.T) {
	customError := errors.New("custom close error")
	errorFile := NewErrorFile(customError)

	err := errorFile.Close()
	assert.Equal(t, customError, err)
}

func TestErrorFile_Stat(t *testing.T) {
	customError := errors.New("custom stat error")
	errorFile := NewErrorFile(customError)

	fileInfo, err := errorFile.Stat()
	assert.Equal(t, customError, err)
	assert.Nil(t, fileInfo)
}

func TestErrorFile_ReadDir(t *testing.T) {
	customError := errors.New("custom readdir error")
	errorFile := NewErrorFile(customError)

	entries, err := errorFile.ReadDir(10)
	assert.Equal(t, customError, err)
	assert.Nil(t, entries)
}

func TestErrorFile_Seek(t *testing.T) {
	customError := errors.New("custom seek error")
	errorFile := NewErrorFile(customError)

	pos, err := errorFile.Seek(0, io.SeekStart)
	assert.Equal(t, customError, err)
	assert.Equal(t, int64(0), pos)
}

func TestErrorFile_Write(t *testing.T) {
	customError := errors.New("custom write error")
	errorFile := NewErrorFile(customError)

	data := []byte("test data")
	n, err := errorFile.Write(data)
	assert.Equal(t, customError, err)
	assert.Equal(t, 0, n)
}

func TestFileInfo_Interface(t *testing.T) {
	name := "test.txt"
	size := int64(123)
	fileInfo := &fileInfo{name: name, size: size}

	// Test all fileInfo methods
	assert.Equal(t, name, fileInfo.Name())
	assert.Equal(t, size, fileInfo.Size())
	assert.Equal(t, os.FileMode(0444), fileInfo.Mode())
	assert.Equal(t, time.Time{}, fileInfo.ModTime())
	assert.False(t, fileInfo.IsDir())
	assert.Nil(t, fileInfo.Sys())
}

func TestFile_ConcurrentAccess(t *testing.T) {
	content := []byte("Hello, World!")
	file := NewFile(content, "test.txt")

	// Test concurrent reads
	done := make(chan bool, 3)

	go func() {
		buf := make([]byte, 5)
		_, err := file.Read(buf)
		assert.NoError(t, err)
		done <- true
	}()

	go func() {
		_, err := file.Seek(0, io.SeekStart)
		assert.NoError(t, err)
		done <- true
	}()

	go func() {
		_, err := file.Stat()
		assert.NoError(t, err)
		done <- true
	}()

	// Wait for all goroutines to complete
	for range 3 {
		<-done
	}
}

func TestFile_EdgeCases(t *testing.T) {
	t.Run("file with nil data", func(t *testing.T) {
		file := NewFile(nil, "nil.txt")
		assert.NotNil(t, file)
		assert.Equal(t, int64(0), file.pos)
		assert.False(t, file.closed)

		// Test reading from nil data
		buf := make([]byte, 10)
		n, err := file.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)

		// Test seeking
		pos, err := file.Seek(0, io.SeekEnd)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), pos)
	})

	t.Run("file with empty name", func(t *testing.T) {
		file := NewFile([]byte("test"), "")
		fileInfo, err := file.Stat()
		assert.NoError(t, err)
		assert.Equal(t, "", fileInfo.Name())
	})

	t.Run("large file operations", func(t *testing.T) {
		largeData := make([]byte, 10000)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		file := NewFile(largeData, "large.txt")

		// Test reading large chunks
		buf := make([]byte, 1000)
		n, err := file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 1000, n)

		// Test seeking to middle
		pos, err := file.Seek(5000, io.SeekStart)
		assert.NoError(t, err)
		assert.Equal(t, int64(5000), pos)

		// Test reading from middle
		n, err = file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 1000, n)
	})
}

func TestWriteCloser(t *testing.T) {
	t.Run("normal write closer", func(t *testing.T) {
		var buf bytes.Buffer
		wc := NewWriteCloser(&buf)

		// Test Write
		data := []byte("test data")
		n, err := wc.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, data, buf.Bytes())

		// Test Close
		err = wc.Close()
		assert.NoError(t, err)

		// Test Write after Close
		_, err = wc.Write([]byte("more data"))
		assert.Error(t, err)
		assert.Equal(t, os.ErrClosed, err)

		// Test Close after Close
		err = wc.Close()
		assert.Error(t, err)
		assert.Equal(t, os.ErrClosed, err)
	})

	t.Run("error write closer", func(t *testing.T) {
		customError := errors.New("custom error")
		wc := NewErrorWriteCloser(customError)

		// Test Write always returns error
		_, err := wc.Write([]byte("test"))
		assert.Error(t, err)
		assert.Equal(t, customError, err)

		// Test Close always returns error
		err = wc.Close()
		assert.Error(t, err)
		assert.Equal(t, customError, err)
	})

	t.Run("close error write closer", func(t *testing.T) {
		var buf bytes.Buffer
		closeError := errors.New("close error")
		wc := NewCloseErrorWriteCloser(&buf, closeError)

		// Test Write works normally
		data := []byte("test data")
		n, err := wc.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, data, buf.Bytes())

		// Test Close returns error
		err = wc.Close()
		assert.Error(t, err)
		assert.Equal(t, closeError, err)
	})
}

func TestFile_AdditionalMethods(t *testing.T) {
	t.Run("test Bytes method", func(t *testing.T) {
		// Test Bytes method returns the current file content
		data := []byte("Hello, World!")
		file := NewFile(data, "test.txt")

		result := file.Bytes()
		assert.Equal(t, data, result)

		// Test that Bytes returns the actual data (not a copy)
		// Since Bytes() returns the underlying slice, modifying it affects the file
		result[0] = 'X'
		assert.Equal(t, []byte("Xello, World!"), file.Bytes())
		assert.Equal(t, []byte("Xello, World!"), result)
	})

	t.Run("test Reset method", func(t *testing.T) {
		file := NewFile([]byte("Hello, World!"), "test.txt")

		// Move position to middle of file
		file.Seek(5, io.SeekStart)
		assert.Equal(t, int64(5), file.pos)

		// Reset position to beginning
		file.Reset()
		assert.Equal(t, int64(0), file.pos)

		// Verify we can read from beginning after reset
		buf := make([]byte, 5)
		n, err := file.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, []byte("Hello"), buf)
	})

	t.Run("test Truncate method", func(t *testing.T) {
		file := NewFile([]byte("Hello, World!"), "test.txt")

		// Truncate to shorter length
		file.Truncate(5)
		assert.Equal(t, []byte("Hello"), file.Bytes())
		assert.Equal(t, int64(0), file.pos) // Position should not change

		// Truncate to longer length (should not change anything)
		file.Truncate(10)
		assert.Equal(t, []byte("Hello"), file.Bytes())

		// Truncate to exact length
		file.Truncate(5)
		assert.Equal(t, []byte("Hello"), file.Bytes())

		// Test truncate when position is beyond new size
		file.Seek(10, io.SeekStart)
		file.Truncate(3)
		assert.Equal(t, int64(3), file.pos) // Position should be adjusted
		assert.Equal(t, []byte("Hel"), file.Bytes())
	})

	t.Run("test Truncate with position adjustment", func(t *testing.T) {
		file := NewFile([]byte("Hello, World!"), "test.txt")

		// Move position beyond truncate point
		file.Seek(8, io.SeekStart)
		assert.Equal(t, int64(8), file.pos)

		// Truncate to position before current position
		file.Truncate(5)
		assert.Equal(t, int64(5), file.pos) // Position should be adjusted
		assert.Equal(t, []byte("Hello"), file.Bytes())
	})
}

func TestErrorReadWriteCloser(t *testing.T) {
	t.Run("test NewErrorReadWriteCloser", func(t *testing.T) {
		testErr := errors.New("test error")
		errorRW := NewErrorReadWriteCloser(testErr)

		assert.NotNil(t, errorRW)
		assert.Equal(t, testErr, errorRW.Err)
	})

	t.Run("test Read method", func(t *testing.T) {
		testErr := errors.New("read error")
		errorRW := NewErrorReadWriteCloser(testErr)

		buf := make([]byte, 10)
		n, err := errorRW.Read(buf)

		assert.Equal(t, 0, n)
		assert.Equal(t, testErr, err)
	})

	t.Run("test Write method", func(t *testing.T) {
		testErr := errors.New("write error")
		errorRW := NewErrorReadWriteCloser(testErr)

		data := []byte("test data")
		n, err := errorRW.Write(data)

		assert.Equal(t, 0, n)
		assert.Equal(t, testErr, err)
	})

	t.Run("test Close method", func(t *testing.T) {
		testErr := errors.New("close error")
		errorRW := NewErrorReadWriteCloser(testErr)

		err := errorRW.Close()

		assert.Equal(t, testErr, err)
	})

	t.Run("test with different error types", func(t *testing.T) {
		// Test with os.ErrClosed
		errorRW := NewErrorReadWriteCloser(os.ErrClosed)

		buf := make([]byte, 10)
		n, err := errorRW.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, os.ErrClosed, err)

		n, err = errorRW.Write(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, os.ErrClosed, err)

		err = errorRW.Close()
		assert.Equal(t, os.ErrClosed, err)
	})

	t.Run("test with nil error", func(t *testing.T) {
		errorRW := NewErrorReadWriteCloser(nil)

		buf := make([]byte, 10)
		n, err := errorRW.Read(buf)
		assert.Equal(t, 0, n)
		assert.Nil(t, err)

		n, err = errorRW.Write(buf)
		assert.Equal(t, 0, n)
		assert.Nil(t, err)

		err = errorRW.Close()
		assert.Nil(t, err)
	})
}

func TestErrorWriteAfterN(t *testing.T) {
	t.Run("test NewErrorWriteAfterN", func(t *testing.T) {
		testErr := errors.New("write error")
		writer := NewErrorWriteAfterN(3, testErr)

		assert.NotNil(t, writer)
		assert.Equal(t, 3, writer.N)
		assert.Equal(t, testErr, writer.Err)
		assert.Equal(t, 0, writer.writeCount)
		assert.Equal(t, 0, writer.totalBytes)
	})

	t.Run("test successful writes before N", func(t *testing.T) {
		testErr := errors.New("write error after 3")
		writer := NewErrorWriteAfterN(3, testErr)

		// First write should succeed
		data1 := []byte("test1")
		n, err := writer.Write(data1)
		assert.NoError(t, err)
		assert.Equal(t, len(data1), n)
		assert.Equal(t, 1, writer.WriteCount())
		assert.Equal(t, len(data1), writer.TotalBytes())

		// Second write should succeed
		data2 := []byte("test2")
		n, err = writer.Write(data2)
		assert.NoError(t, err)
		assert.Equal(t, len(data2), n)
		assert.Equal(t, 2, writer.WriteCount())
		assert.Equal(t, len(data1)+len(data2), writer.TotalBytes())

		// Third write should succeed
		data3 := []byte("test3")
		n, err = writer.Write(data3)
		assert.NoError(t, err)
		assert.Equal(t, len(data3), n)
		assert.Equal(t, 3, writer.WriteCount())
		assert.Equal(t, len(data1)+len(data2)+len(data3), writer.TotalBytes())
	})

	t.Run("test error after N writes", func(t *testing.T) {
		testErr := errors.New("write error after 2")
		writer := NewErrorWriteAfterN(2, testErr)

		// First two writes should succeed
		writer.Write([]byte("data1"))
		writer.Write([]byte("data2"))

		// Third write should fail
		n, err := writer.Write([]byte("data3"))
		assert.Error(t, err)
		assert.Equal(t, testErr, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 3, writer.WriteCount())

		// Fourth write should also fail
		n, err = writer.Write([]byte("data4"))
		assert.Error(t, err)
		assert.Equal(t, testErr, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 4, writer.WriteCount())
	})

	t.Run("test Write with N=0 (always fails)", func(t *testing.T) {
		testErr := errors.New("immediate error")
		writer := NewErrorWriteAfterN(0, testErr)

		// First write should fail immediately
		n, err := writer.Write([]byte("data"))
		assert.Error(t, err)
		assert.Equal(t, testErr, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 1, writer.WriteCount())
		assert.Equal(t, 0, writer.TotalBytes())
	})

	t.Run("test Write with N=1", func(t *testing.T) {
		testErr := errors.New("error after one")
		writer := NewErrorWriteAfterN(1, testErr)

		// First write succeeds
		data := []byte("first")
		n, err := writer.Write(data)
		assert.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, 1, writer.WriteCount())
		assert.Equal(t, len(data), writer.TotalBytes())

		// Second write fails
		n, err = writer.Write([]byte("second"))
		assert.Error(t, err)
		assert.Equal(t, testErr, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 2, writer.WriteCount())
		assert.Equal(t, len(data), writer.TotalBytes()) // Total bytes unchanged
	})

	t.Run("test Reset method", func(t *testing.T) {
		testErr := errors.New("error after reset")
		writer := NewErrorWriteAfterN(2, testErr)

		// Perform some writes
		writer.Write([]byte("data1"))
		writer.Write([]byte("data2"))
		assert.Equal(t, 2, writer.WriteCount())
		assert.Greater(t, writer.TotalBytes(), 0)

		// Reset the counters
		writer.Reset()
		assert.Equal(t, 0, writer.WriteCount())
		assert.Equal(t, 0, writer.TotalBytes())

		// Should be able to write again successfully
		n, err := writer.Write([]byte("new data"))
		assert.NoError(t, err)
		assert.Equal(t, 8, n)
		assert.Equal(t, 1, writer.WriteCount())
		assert.Equal(t, 8, writer.TotalBytes())
	})

	t.Run("test WriteCount and TotalBytes tracking", func(t *testing.T) {
		writer := NewErrorWriteAfterN(10, errors.New("error"))

		// Write different sized data
		sizes := []int{5, 10, 15, 20}
		totalBytes := 0

		for i, size := range sizes {
			data := make([]byte, size)
			n, err := writer.Write(data)
			assert.NoError(t, err)
			assert.Equal(t, size, n)
			totalBytes += size

			assert.Equal(t, i+1, writer.WriteCount())
			assert.Equal(t, totalBytes, writer.TotalBytes())
		}
	})

	t.Run("test with empty data writes", func(t *testing.T) {
		testErr := errors.New("error")
		writer := NewErrorWriteAfterN(2, testErr)

		// Write empty data (should still count as a write)
		n, err := writer.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 1, writer.WriteCount())
		assert.Equal(t, 0, writer.TotalBytes())

		// Second write with empty data
		n, err = writer.Write([]byte{})
		assert.NoError(t, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 2, writer.WriteCount())
		assert.Equal(t, 0, writer.TotalBytes())

		// Third write should fail
		n, err = writer.Write([]byte{})
		assert.Error(t, err)
		assert.Equal(t, testErr, err)
		assert.Equal(t, 0, n)
		assert.Equal(t, 3, writer.WriteCount())
	})

	t.Run("test with large N value", func(t *testing.T) {
		writer := NewErrorWriteAfterN(1000, errors.New("error"))

		// Should succeed for many writes
		for range 100 {
			n, err := writer.Write([]byte("data"))
			assert.NoError(t, err)
			assert.Equal(t, 4, n)
		}

		assert.Equal(t, 100, writer.WriteCount())
		assert.Equal(t, 400, writer.TotalBytes())
	})
}

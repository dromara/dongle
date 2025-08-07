// Package mock provides mock implementations for testing file operations and I/O interfaces.
// It includes mock files, readers, writers, and error scenarios to facilitate unit testing
// of file-based operations without requiring actual file system access.
package mock

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"time"
)

// File is a mock implementation of the fs.File interface for testing purposes.
// It provides an in-memory file representation that can be used to simulate
// file operations without touching the actual file system.
type File struct {
	data   []byte // File content stored in memory
	pos    int64  // Current read/write position
	closed bool   // Whether the file has been closed
	name   string // File name for identification
}

// NewFile creates a new mock file with the specified data and name.
// This function is commonly used in tests to create file-like objects
// that can be passed to functions expecting file interfaces.
func NewFile(data []byte, name string) *File {
	return &File{data: data, name: name}
}

// Read implements the io.Reader interface for mock file operations.
// It reads data from the current position and advances the position accordingly.
// Returns os.ErrClosed if the file has been closed, or io.EOF when reaching the end.
func (f *File) Read(p []byte) (int, error) {
	if f.closed {
		return 0, os.ErrClosed
	}
	if f.pos >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.pos:])
	f.pos += int64(n)
	return n, nil
}

// Close implements the io.Closer interface for mock file operations.
// Marks the file as closed, preventing further read operations.
func (f *File) Close() error {
	f.closed = true
	return nil
}

// Stat returns file information for the mock file.
// Creates a fileInfo object with the file's name and size based on data length.
func (f *File) Stat() (os.FileInfo, error) {
	return &fileInfo{name: f.name, size: int64(len(f.data))}, nil
}

// ReadDir implements the fs.ReadDirFile interface.
// Since this mock represents a regular file, not a directory, it always returns an error.
func (f *File) ReadDir(count int) ([]fs.DirEntry, error) {
	return nil, errors.New("not a directory")
}

// Seek implements the io.Seeker interface for mock file operations.
// Allows positioning the file pointer at different locations within the file.
// Supports seeking from start, current position, or end of file.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	if f.closed {
		return 0, os.ErrClosed
	}

	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = f.pos + offset
	case io.SeekEnd:
		newPos = int64(len(f.data)) + offset
	default:
		return 0, errors.New("invalid whence")
	}

	if newPos < 0 {
		return 0, errors.New("negative position")
	}

	f.pos = newPos
	return f.pos, nil
}

// Write implements the io.Writer interface for mock file operations.
// It writes data to the current position and advances the position accordingly.
// If writing beyond the current data length, the file is extended.
// Returns os.ErrClosed if the file has been closed.
func (f *File) Write(p []byte) (n int, err error) {
	if f.closed {
		return 0, os.ErrClosed
	}

	// If writing beyond current data length, extend the data slice
	if f.pos+int64(len(p)) > int64(len(f.data)) {
		newData := make([]byte, f.pos+int64(len(p)))
		copy(newData, f.data)
		f.data = newData
	}

	// Write data at current position
	copy(f.data[f.pos:], p)
	f.pos += int64(len(p))

	// If we wrote at position 0 and the new data is shorter than the original,
	// truncate the data to avoid keeping old content
	if f.pos == int64(len(p)) && f.pos < int64(len(f.data)) {
		f.data = f.data[:f.pos]
	}

	return len(p), nil
}

// Bytes returns the current file content (for testing)
func (f *File) Bytes() []byte {
	return f.data
}

// Reset resets the file position to the beginning
func (f *File) Reset() {
	f.pos = 0
}

// Truncate truncates the file to the specified size
func (f *File) Truncate(n int) {
	if n < len(f.data) {
		f.data = f.data[:n]
		if f.pos > int64(n) {
			f.pos = int64(n)
		}
	}
}

// ErrorFile is a mock file implementation that always returns errors.
// This is useful for testing error handling paths in code that operates on files.
type ErrorFile struct {
	err error // The error to return for all operations
}

// NewErrorFile creates a new error file that will return the specified error
// for all file operations. This is commonly used to test error scenarios.
func NewErrorFile(err error) *ErrorFile {
	return &ErrorFile{err: err}
}

// Read always returns the configured error, simulating a file read failure.
func (f *ErrorFile) Read(p []byte) (int, error) {
	return 0, f.err
}

// Close always returns the configured error, simulating a file close failure.
func (f *ErrorFile) Close() error {
	return f.err
}

// Stat always returns the configured error, simulating a file stat failure.
func (f *ErrorFile) Stat() (os.FileInfo, error) {
	return nil, f.err
}

// ReadDir always returns the configured error, simulating a directory read failure.
func (f *ErrorFile) ReadDir(count int) ([]fs.DirEntry, error) {
	return nil, f.err
}

// Seek always returns the configured error, simulating a file seek failure.
func (f *ErrorFile) Seek(offset int64, whence int) (int64, error) {
	return 0, f.err
}

// Write always returns the configured error, simulating a file write failure.
func (f *ErrorFile) Write(p []byte) (n int, err error) {
	return 0, f.err
}

// fileInfo implements the os.FileInfo interface for mock file information.
// Provides basic file metadata for mock files used in testing.
type fileInfo struct {
	name string // File name
	size int64  // File size in bytes
}

// Name returns the file name.
func (fi *fileInfo) Name() string { return fi.name }

// Size returns the file size in bytes.
func (fi *fileInfo) Size() int64 { return fi.size }

// Mode returns a read-only file mode (0444) for mock files.
func (fi *fileInfo) Mode() os.FileMode { return 0444 }

// ModTime returns a zero time value for mock files.
func (fi *fileInfo) ModTime() time.Time { return time.Time{} }

// IsDir returns false since mock files represent regular files, not directories.
func (fi *fileInfo) IsDir() bool { return false }

// Sys returns nil for mock files as they don't have underlying system-specific data.
func (fi *fileInfo) Sys() interface{} { return nil }

// WriteCloser is a mock implementation of io.WriteCloser for testing purposes.
// It wraps an io.Writer and adds close functionality with state tracking.
type WriteCloser struct {
	w      io.Writer // Underlying writer to delegate writes to
	closed bool      // Whether the WriteCloser has been closed
}

// NewWriteCloser creates a new mock WriteCloser that wraps the provided io.Writer.
// This is useful for testing code that requires both write and close operations.
func NewWriteCloser(w io.Writer) *WriteCloser {
	return &WriteCloser{w: w}
}

// Write implements the io.Writer interface by delegating to the underlying writer.
// Returns os.ErrClosed if the WriteCloser has been closed.
func (wc *WriteCloser) Write(p []byte) (n int, err error) {
	if wc.closed {
		return 0, os.ErrClosed
	}
	return wc.w.Write(p)
}

// Close implements the io.Closer interface for the mock WriteCloser.
// Marks the WriteCloser as closed and prevents further write operations.
func (wc *WriteCloser) Close() error {
	if wc.closed {
		return os.ErrClosed
	}
	wc.closed = true
	return nil
}

// ErrorWriteCloser is a mock io.WriteCloser that always returns errors.
// Useful for testing error handling in code that writes to files or other writers.
type ErrorWriteCloser struct {
	err error // The error to return for all operations
}

// NewErrorWriteCloser creates a new error WriteCloser that will return
// the specified error for all write and close operations.
func NewErrorWriteCloser(err error) *ErrorWriteCloser {
	return &ErrorWriteCloser{err: err}
}

// Write always returns the configured error, simulating a write failure.
func (wc *ErrorWriteCloser) Write(p []byte) (n int, err error) {
	return 0, wc.err
}

// Close always returns the configured error, simulating a close failure.
func (wc *ErrorWriteCloser) Close() error {
	return wc.err
}

// CloseErrorWriteCloser is a mock io.WriteCloser where only the Close() method returns an error.
// This is useful for testing scenarios where writes succeed but closing fails.
type CloseErrorWriteCloser struct {
	w   io.Writer // Underlying writer for successful write operations
	err error     // Error to return when Close() is called
}

// NewCloseErrorWriteCloser creates a new WriteCloser that writes successfully
// but returns an error when Close() is called. This simulates partial failure scenarios.
func NewCloseErrorWriteCloser(w io.Writer, err error) *CloseErrorWriteCloser {
	return &CloseErrorWriteCloser{w: w, err: err}
}

// Write implements the io.Writer interface by delegating to the underlying writer.
// This method always succeeds, allowing testing of close error scenarios.
func (wc *CloseErrorWriteCloser) Write(p []byte) (n int, err error) {
	return wc.w.Write(p)
}

// Close always returns the configured error, simulating a close failure
// while allowing writes to succeed.
func (wc *CloseErrorWriteCloser) Close() error {
	return wc.err
}

// ErrorReadWriteCloser is a mock that implements io.Reader, io.Writer, and io.Closer interfaces,
// always returning the specified error for all operations. This is useful for testing
// scenarios where all I/O operations fail, such as network failures or corrupted streams.
type ErrorReadWriteCloser struct {
	Err error // The error to return for all read, write, and close operations
}

// NewErrorReadWriteCloser creates a new ErrorReadWriteCloser that will return
// the specified error for all read, write, and close operations. This mock is
// particularly useful for testing error handling in streaming operations where
// all I/O methods need to fail consistently.
func NewErrorReadWriteCloser(err error) *ErrorReadWriteCloser {
	return &ErrorReadWriteCloser{Err: err}
}

// Read always returns the configured error, simulating a read failure.
// This method implements the io.Reader interface for consistent error testing.
func (e *ErrorReadWriteCloser) Read(p []byte) (int, error) { return 0, e.Err }

// Write always returns the configured error, simulating a write failure.
// This method implements the io.Writer interface for consistent error testing.
func (e *ErrorReadWriteCloser) Write(p []byte) (int, error) { return 0, e.Err }

// Close always returns the configured error, simulating a close failure.
// This method implements the io.Closer interface for consistent error testing.
func (e *ErrorReadWriteCloser) Close() error { return e.Err }

// Package mock provides mock implementations for testing purposes in the dongle package.
// It includes mock implementations of file system interfaces, hash interfaces,
// and I/O operations that can be used to simulate various scenarios during testing.
//
// The mock package is designed to support comprehensive testing of the dongle
// library by providing:
//
//   - File system mocks: Mock file implementations that simulate file operations
//     without touching the actual file system, including error scenarios
//   - Hash mocks: Mock hash implementations that can simulate hash operation failures
//     for testing error handling paths
//   - I/O mocks: Mock implementations of io.Reader, io.Writer, and io.Closer
//     interfaces with configurable error conditions
//
// These mocks are particularly useful for:
//   - Testing error handling without requiring actual system failures
//   - Isolating code under test from external dependencies
//   - Creating predictable test scenarios with controlled behavior
//   - Verifying that error conditions are properly handled and propagated
//
// Example usage:
//
//	file := mock.NewFile([]byte("test data"), "test.txt")
//	hasher := mock.NewErrorHasher(errors.New("hash error"))
//	writer := mock.NewWriteCloser(os.Stdout)
package mock

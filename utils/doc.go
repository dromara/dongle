// Package utils provides utility functions for the dongle package.
// It includes high-performance conversion functions between strings and byte slices
// that use unsafe operations to achieve zero-copy conversions for better performance.
//
// The utils package is designed to support the dongle library's performance requirements
// by providing:
//
//   - Zero-copy string to byte slice conversion: String2Bytes() function that converts
//     strings to byte slices without memory allocation using unsafe operations
//   - Zero-copy byte slice to string conversion: Bytes2String() function that converts
//     byte slices to strings without memory allocation using unsafe operations
//
// These utility functions are particularly useful for:
//   - High-performance cryptographic operations where memory allocation overhead matters
//   - Converting between string and byte representations frequently in hot paths
//   - Reducing garbage collection pressure in performance-critical code
//   - Maintaining compatibility with standard Go string/byte slice operations
//
// WARNING: The conversion functions use unsafe operations and have specific requirements:
//   - String2Bytes() returns a read-only byte slice - modifying it may cause undefined behavior
//   - Bytes2String() requires the input byte slice to remain unchanged after conversion
//   - These functions rely on Go's current runtime implementation and may not be safe
//     across all Go versions
//   - For safety-critical applications, prefer standard []byte(s) and string(b) conversions
//
// Example usage:
//
//	// Zero-copy string to bytes conversion
//	data := utils.String2Bytes("hello world")
//	// WARNING: data is read-only, do not modify
//
//	// Zero-copy bytes to string conversion
//	text := utils.Bytes2String([]byte{'h', 'e', 'l', 'l', 'o'})
//	// WARNING: original byte slice must not be modified
package utils

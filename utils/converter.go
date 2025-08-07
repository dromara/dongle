package utils

import (
	"unsafe"
)

// String2Bytes converts string to byte slice without memory allocation (zero-copy).
//
// WARNING: The returned []byte must be treated as read-only.
// Modifying the returned slice may break Go's string immutability guarantee and cause undefined behavior.
// This method uses unsafe tricks and relies on Go's current runtime implementation.
// It is not guaranteed to be safe across all Go versions.
// Use only when you are sure the []byte will not be modified.
// For safety, prefer []byte(s) if you need a writable copy.
func String2Bytes(s string) []byte {
	if len(s) == 0 {
		return []byte("")
	}
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

// Bytes2String converts a byte slice to string without memory allocation (zero-copy).
//
// WARNING: The input []byte must not be modified after conversion, as strings in Go are immutable.
// This method uses unsafe tricks and relies on Go's current runtime implementation.
// It is not guaranteed to be safe across all Go versions.
// For safety, prefer string(b) if you need a copy.
func Bytes2String(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return *(*string)(unsafe.Pointer(&b))
}

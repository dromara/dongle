package utils

import (
	"fmt"
	"reflect"
	"unsafe"
)

// ExampleString2Bytes demonstrates basic string to bytes conversion
func ExampleString2Bytes() {
	str := "hello world"
	bytes := String2Bytes(str)

	fmt.Printf("Original string: %s\n", str)
	fmt.Printf("Converted bytes: %v\n", bytes)
	fmt.Printf("Bytes as string: %s\n", string(bytes))
	// Output:
	// Original string: hello world
	// Converted bytes: [104 101 108 108 111 32 119 111 114 108 100]
	// Bytes as string: hello world
}

// ExampleString2Bytes_emptyString demonstrates handling of empty strings
func ExampleString2Bytes_emptyString() {
	str := ""
	bytes := String2Bytes(str)

	fmt.Printf("Empty string length: %d\n", len(str))
	fmt.Printf("Converted bytes length: %d\n", len(bytes))
	fmt.Printf("Bytes: %v\n", bytes)
	// Output:
	// Empty string length: 0
	// Converted bytes length: 0
	// Bytes: []
}

// ExampleString2Bytes_unicodeString demonstrates Unicode string conversion
func ExampleString2Bytes_unicodeString() {
	str := "你好世界"
	bytes := String2Bytes(str)

	fmt.Printf("Unicode string: %s\n", str)
	fmt.Printf("Byte length: %d\n", len(bytes))
	fmt.Printf("String length: %d\n", len(str))
	// Output:
	// Unicode string: 你好世界
	// Byte length: 12
	// String length: 12
}

// ExampleString2Bytes_zeroCopy demonstrates zero-copy behavior
func ExampleString2Bytes_zeroCopy() {
	str := "zero copy test"
	bytes := String2Bytes(str)

	// Get the underlying data pointers to verify zero-copy
	strHeader := (*reflect.StringHeader)(unsafe.Pointer(&str))
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&bytes))

	fmt.Printf("Same data pointer: %t\n", strHeader.Data == sliceHeader.Data)
	fmt.Printf("Same length: %t\n", strHeader.Len == sliceHeader.Len)
	// Output:
	// Same data pointer: true
	// Same length: true
}

// ExampleBytes2String demonstrates basic bytes to string conversion
func ExampleBytes2String() {
	bytes := []byte{104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100}
	str := Bytes2String(bytes)

	fmt.Printf("Original bytes: %v\n", bytes)
	fmt.Printf("Converted string: %s\n", str)
	fmt.Printf("String length: %d\n", len(str))
	// Output:
	// Original bytes: [104 101 108 108 111 32 119 111 114 108 100]
	// Converted string: hello world
	// String length: 11
}

// ExampleBytes2String_emptyBytes demonstrates handling of empty byte slices
func ExampleBytes2String_emptyBytes() {
	bytes := []byte{}
	str := Bytes2String(bytes)

	fmt.Printf("Empty bytes length: %d\n", len(bytes))
	fmt.Printf("Converted string length: %d\n", len(str))
	fmt.Printf("String: '%s'\n", str)
	// Output:
	// Empty bytes length: 0
	// Converted string length: 0
	// String: ''
}

// ExampleBytes2String_unicodeBytes demonstrates Unicode bytes conversion
func ExampleBytes2String_unicodeBytes() {
	// UTF-8 encoded bytes for "你好世界"
	bytes := []byte{228, 189, 160, 229, 165, 189, 228, 184, 150, 231, 149, 140}
	str := Bytes2String(bytes)

	fmt.Printf("Unicode bytes length: %d\n", len(bytes))
	fmt.Printf("Converted string: %s\n", str)
	fmt.Printf("String character count: %d\n", len([]rune(str)))
	// Output:
	// Unicode bytes length: 12
	// Converted string: 你好世界
	// String character count: 4
}

// ExampleBytes2String_zeroCopy demonstrates zero-copy behavior
func ExampleBytes2String_zeroCopy() {
	bytes := []byte("zero copy test")
	str := Bytes2String(bytes)

	// Get the underlying data pointers to verify zero-copy
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	strHeader := (*reflect.StringHeader)(unsafe.Pointer(&str))

	fmt.Printf("Same data pointer: %t\n", sliceHeader.Data == strHeader.Data)
	fmt.Printf("Same length: %t\n", sliceHeader.Len == strHeader.Len)
	// Output:
	// Same data pointer: true
	// Same length: true
}

// ExampleString2Bytes_performance demonstrates performance comparison
func ExampleString2Bytes_performance() {
	str := "performance test string"

	// Zero-copy conversion
	bytes1 := String2Bytes(str)

	// Standard conversion (with copy)
	bytes2 := []byte(str)

	fmt.Printf("Zero-copy result: %s\n", string(bytes1))
	fmt.Printf("Standard result: %s\n", string(bytes2))
	fmt.Printf("Results equal: %t\n", string(bytes1) == string(bytes2))
	// Output:
	// Zero-copy result: performance test string
	// Standard result: performance test string
	// Results equal: true
}

// ExampleBytes2String_performance demonstrates performance comparison
func ExampleBytes2String_performance() {
	bytes := []byte("performance test bytes")

	// Zero-copy conversion
	str1 := Bytes2String(bytes)

	// Standard conversion (with copy)
	str2 := string(bytes)

	fmt.Printf("Zero-copy result: %s\n", str1)
	fmt.Printf("Standard result: %s\n", str2)
	fmt.Printf("Results equal: %t\n", str1 == str2)
	// Output:
	// Zero-copy result: performance test bytes
	// Standard result: performance test bytes
	// Results equal: true
}

// ExampleString2Bytes_roundTrip demonstrates round-trip conversion
func ExampleString2Bytes_roundTrip() {
	original := "round trip test"

	// String -> Bytes -> String
	bytes := String2Bytes(original)
	result := Bytes2String(bytes)

	fmt.Printf("Original: %s\n", original)
	fmt.Printf("Round trip result: %s\n", result)
	fmt.Printf("Equal: %t\n", original == result)
	// Output:
	// Original: round trip test
	// Round trip result: round trip test
	// Equal: true
}

// ExampleBytes2String_roundTrip demonstrates round-trip conversion
func ExampleBytes2String_roundTrip() {
	original := []byte("round trip bytes test")

	// Bytes -> String -> Bytes
	str := Bytes2String(original)
	result := String2Bytes(str)

	fmt.Printf("Original: %s\n", string(original))
	fmt.Printf("Round trip result: %s\n", string(result))
	fmt.Printf("Equal: %t\n", string(original) == string(result))
	// Output:
	// Original: round trip bytes test
	// Round trip result: round trip bytes test
	// Equal: true
}

// ExampleString2Bytes_specialCharacters demonstrates handling special characters
func ExampleString2Bytes_specialCharacters() {
	str := "Hello\nWorld\t!@#$%^&*()"
	bytes := String2Bytes(str)

	fmt.Printf("Special chars string: %q\n", str)
	fmt.Printf("Bytes length: %d\n", len(bytes))
	fmt.Printf("Back to string: %q\n", string(bytes))
	// Output:
	// Special chars string: "Hello\nWorld\t!@#$%^&*()"
	// Bytes length: 22
	// Back to string: "Hello\nWorld\t!@#$%^&*()"
}

// ExampleBytes2String_specialCharacters demonstrates handling special characters
func ExampleBytes2String_specialCharacters() {
	// Bytes containing newline, tab, and special characters
	bytes := []byte{72, 101, 108, 108, 111, 10, 87, 111, 114, 108, 100, 9, 33, 64, 35}
	str := Bytes2String(bytes)

	fmt.Printf("Special bytes: %v\n", bytes)
	fmt.Printf("Converted string: %q\n", str)
	fmt.Printf("String length: %d\n", len(str))
	// Output:
	// Special bytes: [72 101 108 108 111 10 87 111 114 108 100 9 33 64 35]
	// Converted string: "Hello\nWorld\t!@#"
	// String length: 15
}

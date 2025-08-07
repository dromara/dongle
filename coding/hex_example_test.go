package coding_test

import (
	"fmt"
	"os"

	"github.com/dromara/dongle/coding"
)

func ExampleEncoder_ByHex() {
	// Encode a string using hex
	encoder := coding.NewEncoder().FromString("hello world").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 68656c6c6f20776f726c64
}

func ExampleDecoder_ByHex() {
	// Decode a hex string
	decoder := coding.NewDecoder().FromString("68656c6c6f20776f726c64").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByHex_bytes() {
	// Encode bytes using hex
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 0102030405
}

func ExampleDecoder_ByHex_bytes() {
	// Decode hex bytes
	decoder := coding.NewDecoder().FromBytes([]byte("0102030405")).ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleEncoder_ByHex_file() {
	// Create a temporary file for demonstration
	content := []byte("hello world")
	tmpFile, err := os.CreateTemp("", "hex_example")
	if err != nil {
		fmt.Println("Create temp file error:", err)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write content to file
	if _, err := tmpFile.Write(content); err != nil {
		fmt.Println("Write file error:", err)
		return
	}

	// Reset file position to beginning
	tmpFile.Seek(0, 0)

	// Encode from file
	encoder := coding.NewEncoder().FromFile(tmpFile).ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 68656c6c6f20776f726c64
}

func ExampleDecoder_ByHex_file() {
	// Create a temporary file with encoded content for demonstration
	encodedContent := []byte("68656c6c6f20776f726c64")
	tmpFile, err := os.CreateTemp("", "hex_example")
	if err != nil {
		fmt.Println("Create temp file error:", err)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write encoded content to file
	if _, err := tmpFile.Write(encodedContent); err != nil {
		fmt.Println("Write file error:", err)
		return
	}

	// Reset file position to beginning
	tmpFile.Seek(0, 0)

	// Decode from file
	decoder := coding.NewDecoder().FromFile(tmpFile).ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByHex_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByHex_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByHex_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("A").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: 41
}

func ExampleDecoder_ByHex_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString("41").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: A
}

func ExampleEncoder_ByHex_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()

	fmt.Printf("Original: %s\n", original)
	fmt.Printf("Encoded: %s\n", encoded)
	fmt.Printf("Decoded: %s\n", decoded)
	fmt.Printf("Round-trip successful: %t\n", original == decoded)
	// Output:
	// Original: hello world
	// Encoded: 68656c6c6f20776f726c64
	// Decoded: hello world
	// Round-trip successful: true
}

func ExampleEncoder_ByHex_special_characters() {
	// Encode string with special characters
	encoder := coding.NewEncoder().FromString("Hello, 世界! @#$%^&*()").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Special characters encoded:", encoded)
	// Output: Special characters encoded: 48656c6c6f2c20e4b896e7958c2120402324255e262a2829
}

func ExampleDecoder_ByHex_special_characters() {
	// Decode string with special characters
	decoder := coding.NewDecoder().FromString("48656c6c6f2c20e4b896e7958c2120402324255e262a2829").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Special characters decoded:", decoded)
	// Output: Special characters decoded: Hello, 世界! @#$%^&*()
}

// Additional examples based on Python verification
func ExampleEncoder_ByHex_two_characters() {
	// Encode two characters
	encoder := coding.NewEncoder().FromString("AB").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Two characters encoded:", encoded)
	// Output: Two characters encoded: 4142
}

func ExampleEncoder_ByHex_three_characters() {
	// Encode three characters
	encoder := coding.NewEncoder().FromString("ABC").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Three characters encoded:", encoded)
	// Output: Three characters encoded: 414243
}

func ExampleEncoder_ByHex_four_characters() {
	// Encode four characters
	encoder := coding.NewEncoder().FromString("ABCD").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Four characters encoded:", encoded)
	// Output: Four characters encoded: 41424344
}

func ExampleEncoder_ByHex_five_characters() {
	// Encode five characters
	encoder := coding.NewEncoder().FromString("ABCDE").ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Five characters encoded:", encoded)
	// Output: Five characters encoded: 4142434445
}

func ExampleEncoder_ByHex_zero_bytes() {
	// Encode zero bytes
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Zero bytes encoded:", encoded)
	// Output: Zero bytes encoded: 00000000
}

func ExampleDecoder_ByHex_zero_bytes() {
	// Decode zero bytes
	decoder := coding.NewDecoder().FromString("00000000").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Zero bytes decoded: %v\n", decoded)
	// Output: Zero bytes decoded: [0 0 0 0]
}

func ExampleEncoder_ByHex_max_bytes() {
	// Encode max bytes (255, 255, 255, 255)
	encoder := coding.NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Max bytes encoded:", encoded)
	// Output: Max bytes encoded: ffffffff
}

func ExampleDecoder_ByHex_max_bytes() {
	// Decode max bytes
	decoder := coding.NewDecoder().FromString("ffffffff").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Max bytes decoded: %v\n", decoded)
	// Output: Max bytes decoded: [255 255 255 255]
}

func ExampleEncoder_ByHex_large_bytes() {
	// Encode larger byte array
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}).ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Large bytes encoded:", encoded)
	// Output: Large bytes encoded: 0102030405060708090a
}

func ExampleDecoder_ByHex_large_bytes() {
	// Decode larger byte array
	decoder := coding.NewDecoder().FromString("0102030405060708090a").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Large bytes decoded: %v\n", decoded)
	// Output: Large bytes decoded: [1 2 3 4 5 6 7 8 9 10]
}

func ExampleEncoder_ByHex_mac_address() {
	// Encode MAC address
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x1B, 0x44, 0x11, 0x3A, 0xE7}).ByHex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("MAC address encoded:", encoded)
	// Output: MAC address encoded: 001b44113ae7
}

func ExampleDecoder_ByHex_mac_address() {
	// Decode MAC address
	decoder := coding.NewDecoder().FromString("001b44113ae7").ByHex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("MAC address decoded: %v\n", decoded)
	// Output: MAC address decoded: [0 27 68 17 58 231]
}

package coding_test

import (
	"fmt"
	"os"

	"github.com/dromara/dongle/coding"
)

func ExampleEncoder_ByBase62() {
	// Encode a string using base62
	encoder := coding.NewEncoder().FromString("hello world").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: AAwf93rvy4aWQVw
}

func ExampleDecoder_ByBase62() {
	// Decode a base62 string
	decoder := coding.NewDecoder().FromString("AAwf93rvy4aWQVw").ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase62_bytes() {
	// Encode bytes using base62
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 4iwreH
}

func ExampleDecoder_ByBase62_bytes() {
	// Decode base62 bytes
	decoder := coding.NewDecoder().FromBytes([]byte("4iwreH")).ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleEncoder_ByBase62_file() {
	// Create a temporary file for demonstration
	content := []byte("hello world")
	tmpFile, err := os.CreateTemp("", "base62_example")
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
	encoder := coding.NewEncoder().FromFile(tmpFile).ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: AAwf93rvy4aWQVw
}

func ExampleDecoder_ByBase62_file() {
	// Create a temporary file with encoded content for demonstration
	encodedContent := []byte("AAwf93rvy4aWQVw")
	tmpFile, err := os.CreateTemp("", "base62_example")
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
	decoder := coding.NewDecoder().FromFile(tmpFile).ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase62_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByBase62_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByBase62_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("A").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: 13
}

func ExampleDecoder_ByBase62_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString("13").ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: A
}

func ExampleEncoder_ByBase62_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase62()
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
	// Encoded: AAwf93rvy4aWQVw
	// Decoded: hello world
	// Round-trip successful: true
}

func ExampleEncoder_ByBase62_special_characters() {
	// Encode string with special characters
	encoder := coding.NewEncoder().FromString("Hello, 世界! @#$%^&*()").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Special characters encoded:", encoded)
	// Output: Special characters encoded: mQVVWc16lxQL8tnwWepxNOes08423Rg9
}

func ExampleDecoder_ByBase62_special_characters() {
	// Decode string with special characters
	decoder := coding.NewDecoder().FromString("mQVVWc16lxQL8tnwWepxNOes08423Rg9").ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Special characters decoded:", decoded)
	// Output: Special characters decoded: Hello, 世界! @#$%^&*()
}

// Additional examples based on Python verification
func ExampleEncoder_ByBase62_two_characters() {
	// Encode two characters
	encoder := coding.NewEncoder().FromString("AB").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Two characters encoded:", encoded)
	// Output: Two characters encoded: 4LS
}

func ExampleEncoder_ByBase62_three_characters() {
	// Encode three characters
	encoder := coding.NewEncoder().FromString("ABC").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Three characters encoded:", encoded)
	// Output: Three characters encoded: Hwah
}

func ExampleEncoder_ByBase62_four_characters() {
	// Encode four characters
	encoder := coding.NewEncoder().FromString("ABCD").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Four characters encoded:", encoded)
	// Output: Four characters encoded: 1C5vWe
}

func ExampleEncoder_ByBase62_five_characters() {
	// Encode five characters
	encoder := coding.NewEncoder().FromString("ABCDE").ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Five characters encoded:", encoded)
	// Output: Five characters encoded: 4vwTWoH
}

func ExampleEncoder_ByBase62_zero_bytes() {
	// Encode zero bytes
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Zero bytes encoded:", encoded)
	// Output: Zero bytes encoded: 04
}

func ExampleDecoder_ByBase62_zero_bytes() {
	// Decode zero bytes
	decoder := coding.NewDecoder().FromString("04").ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Zero bytes decoded: %v\n", decoded)
	// Output: Zero bytes decoded: [0 0 0 0]
}

func ExampleEncoder_ByBase62_max_bytes() {
	// Encode max bytes (255, 255, 255, 255)
	encoder := coding.NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Max bytes encoded:", encoded)
	// Output: Max bytes encoded: 4gfFC3
}

func ExampleDecoder_ByBase62_max_bytes() {
	// Decode max bytes
	decoder := coding.NewDecoder().FromString("4gfFC3").ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Max bytes decoded: %v\n", decoded)
	// Output: Max bytes decoded: [255 255 255 255]
}

func ExampleEncoder_ByBase62_large_bytes() {
	// Encode larger byte array
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}).ByBase62()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Large bytes encoded:", encoded)
	// Output: Large bytes encoded: 1TSm0PiyImxIY
}

func ExampleDecoder_ByBase62_large_bytes() {
	// Decode larger byte array
	decoder := coding.NewDecoder().FromString("1TSm0PiyImxIY").ByBase62()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Large bytes decoded: %v\n", decoded)
	// Output: Large bytes decoded: [1 2 3 4 5 6 7 8 9 10]
}

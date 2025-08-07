package coding_test

import (
	"fmt"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/mock"
)

func ExampleEncoder_ByBase58() {
	// Encode a string using base58
	encoder := coding.NewEncoder().FromString("hello world").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: StV1DL6CwTryKyV
}

func ExampleDecoder_ByBase58() {
	// Decode a base58 string
	decoder := coding.NewDecoder().FromString("StV1DL6CwTryKyV").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase58_bytes() {
	// Encode bytes using base58
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 7bWpTW
}

func ExampleDecoder_ByBase58_bytes() {
	// Decode base58 bytes
	decoder := coding.NewDecoder().FromBytes([]byte("7bWpTW")).ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleEncoder_ByBase58_file() {
	// Create a mock file for demonstration
	content := []byte("hello world")
	file := mock.NewFile(content, "base58_example.txt")

	// Encode from file
	encoder := coding.NewEncoder().FromFile(file).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: StV1DL6CwTryKyV
}

func ExampleDecoder_ByBase58_file() {
	// Create a mock file with encoded content for demonstration
	encodedContent := []byte("StV1DL6CwTryKyV")
	file := mock.NewFile(encodedContent, "base58_example.txt")

	// Decode from file
	decoder := coding.NewDecoder().FromFile(file).ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase58_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByBase58_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByBase58_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("A").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: 28
}

func ExampleDecoder_ByBase58_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString("28").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: A
}

func ExampleEncoder_ByBase58_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase58()
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
	// Encoded: StV1DL6CwTryKyV
	// Decoded: hello world
	// Round-trip successful: true
}

func ExampleEncoder_ByBase58_special_characters() {
	// Encode string with special characters
	encoder := coding.NewEncoder().FromString("Hello, 世界! @#$%^&*()").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Special characters encoded:", encoded)
	// Output: Special characters encoded: 7bo9qr44KEksXMGjxN4UdtFPoZP3bc5QC
}

func ExampleDecoder_ByBase58_special_characters() {
	// Decode string with special characters
	decoder := coding.NewDecoder().FromString("7bo9qr44KEksXMGjxN4UdtFPoZP3bc5QC").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Special characters decoded:", decoded)
	// Output: Special characters decoded: Hello, 世界! @#$%^&*()
}

// Additional examples based on Python verification
func ExampleEncoder_ByBase58_two_characters() {
	// Encode two characters
	encoder := coding.NewEncoder().FromString("AB").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Two characters encoded:", encoded)
	// Output: Two characters encoded: 5y3
}

func ExampleEncoder_ByBase58_three_characters() {
	// Encode three characters
	encoder := coding.NewEncoder().FromString("ABC").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Three characters encoded:", encoded)
	// Output: Three characters encoded: NvLz
}

func ExampleEncoder_ByBase58_four_characters() {
	// Encode four characters
	encoder := coding.NewEncoder().FromString("ABCD").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Four characters encoded:", encoded)
	// Output: Four characters encoded: 2fkTDm
}

func ExampleEncoder_ByBase58_five_characters() {
	// Encode five characters
	encoder := coding.NewEncoder().FromString("ABCDE").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Five characters encoded:", encoded)
	// Output: Five characters encoded: 8N2njLQ
}

func ExampleEncoder_ByBase58_zero_bytes() {
	// Encode zero bytes
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Zero bytes encoded:", encoded)
	// Output: Zero bytes encoded: 1111
}

func ExampleDecoder_ByBase58_zero_bytes() {
	// Decode zero bytes
	decoder := coding.NewDecoder().FromString("1111").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Zero bytes decoded: %v\n", decoded)
	// Output: Zero bytes decoded: [0 0 0 0]
}

func ExampleEncoder_ByBase58_max_bytes() {
	// Encode max bytes (255, 255, 255, 255)
	encoder := coding.NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Max bytes encoded:", encoded)
	// Output: Max bytes encoded: 7YXq9G
}

func ExampleDecoder_ByBase58_max_bytes() {
	// Decode max bytes
	decoder := coding.NewDecoder().FromString("7YXq9G").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Max bytes decoded: %v\n", decoded)
	// Output: Max bytes decoded: [255 255 255 255]
}

func ExampleEncoder_ByBase58_large_bytes() {
	// Encode larger byte array
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Large bytes encoded:", encoded)
	// Output: Large bytes encoded: 4HUtbHhN2TkpR
}

func ExampleDecoder_ByBase58_large_bytes() {
	// Decode larger byte array
	decoder := coding.NewDecoder().FromString("4HUtbHhN2TkpR").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Large bytes decoded: %v\n", decoded)
	// Output: Large bytes decoded: [1 2 3 4 5 6 7 8 9 10]
}

func ExampleEncoder_ByBase58_leading_zeros() {
	// Encode bytes with leading zeros
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x01, 0x02, 0x03}).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Leading zeros encoded:", encoded)
	// Output: Leading zeros encoded: 1Ldp
}

func ExampleDecoder_ByBase58_leading_zeros() {
	// Decode bytes with leading zeros
	decoder := coding.NewDecoder().FromString("1Ldp").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Leading zeros decoded: %v\n", decoded)
	// Output: Leading zeros decoded: [0 1 2 3]
}

func ExampleEncoder_ByBase58_binary_data() {
	// Encode binary data
	binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	encoder := coding.NewEncoder().FromBytes(binaryData).ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Binary data encoded:", encoded)
	// Output: Binary data encoded: 13DV616t9R
}

func ExampleDecoder_ByBase58_binary_data() {
	// Decode binary data
	decoder := coding.NewDecoder().FromString("13DV616t9R").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Binary data decoded: %v\n", decoded)
	// Output: Binary data decoded: [0 1 2 3 255 254 253 252]
}

func ExampleEncoder_ByBase58_unicode() {
	// Encode Unicode string
	encoder := coding.NewEncoder().FromString("你好世界").ByBase58()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Unicode encoded:", encoded)
	// Output: Unicode encoded: 5KMpie3K6ztGQYmij
}

func ExampleDecoder_ByBase58_unicode() {
	// Decode Unicode string
	decoder := coding.NewDecoder().FromString("5KMpie3K6ztGQYmij").ByBase58()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Unicode decoded:", decoded)
	// Output: Unicode decoded: 你好世界
}

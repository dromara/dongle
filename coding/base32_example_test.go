package coding_test

import (
	"fmt"
	"os"

	"github.com/dromara/dongle/coding"
)

func ExampleEncoder_ByBase32() {
	// Encode a string using standard base32
	encoder := coding.NewEncoder().FromString("hello world").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: NBSWY3DPEB3W64TMMQ======
}

func ExampleEncoder_ByBase32Hex() {
	// Encode a string using base32 hex alphabet
	encoder := coding.NewEncoder().FromString("hello world").ByBase32Hex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: D1IMOR3F41RMUSJCCG======
}

func ExampleEncoder_ByBase32_bytes() {
	// Encode bytes using standard base32
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: AEBAGBAF
}

func ExampleEncoder_ByBase32Hex_bytes() {
	// Encode bytes using base32 hex alphabet
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByBase32Hex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 04106105
}

func ExampleDecoder_ByBase32() {
	// Decode a base32 string
	decoder := coding.NewDecoder().FromString("NBSWY3DPEB3W64TMMQ======").ByBase32()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleDecoder_ByBase32Hex() {
	// Decode a base32 hex string
	decoder := coding.NewDecoder().FromString("D1IMOR3F41RMUSJCCG======").ByBase32Hex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleDecoder_ByBase32_bytes() {
	// Decode base32 bytes
	decoder := coding.NewDecoder().FromBytes([]byte("AEBAGBAF")).ByBase32()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleDecoder_ByBase32Hex_bytes() {
	// Decode base32 hex bytes
	decoder := coding.NewDecoder().FromBytes([]byte("04106105")).ByBase32Hex()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleEncoder_ByBase32_file() {
	// Create a temporary file for demonstration
	content := []byte("hello world")
	tmpFile, err := os.CreateTemp("", "base32_example")
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
	encoder := coding.NewEncoder().FromFile(tmpFile).ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: NBSWY3DPEB3W64TMMQ======
}

func ExampleDecoder_ByBase32_file() {
	// Create a temporary file with encoded content for demonstration
	encodedContent := []byte("NBSWY3DPEB3W64TMMQ======")
	tmpFile, err := os.CreateTemp("", "base32_example")
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
	decoder := coding.NewDecoder().FromFile(tmpFile).ByBase32()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase32_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByBase32_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByBase32()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByBase32_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("A").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: IE======
}

func ExampleDecoder_ByBase32_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString("IE======").ByBase32()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: A
}

func ExampleEncoder_ByBase32_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase32()
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
	// Encoded: NBSWY3DPEB3W64TMMQ======
	// Decoded: hello world
	// Round-trip successful: true
}

func ExampleEncoder_ByBase32Hex_round_trip() {
	// Demonstrate round-trip encoding and decoding with hex alphabet
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByBase32Hex()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase32Hex()
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
	// Encoded: D1IMOR3F41RMUSJCCG======
	// Decoded: hello world
	// Round-trip successful: true
}

func ExampleEncoder_ByBase32_special_characters() {
	// Encode string with special characters
	encoder := coding.NewEncoder().FromString("Hello, 世界! @#$%^&*()").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Special characters encoded:", encoded)
	// Output: Special characters encoded: JBSWY3DPFQQOJOEW46KYYIJAIARSIJK6EYVCQKI=
}

func ExampleDecoder_ByBase32_special_characters() {
	// Decode string with special characters
	decoder := coding.NewDecoder().FromString("JBSWY3DPFQQOJOEW46KYYIJAIARSIJK6EYVCQKI=").ByBase32()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Special characters decoded:", decoded)
	// Output: Special characters decoded: Hello, 世界! @#$%^&*()
}

// Additional examples based on Python verification
func ExampleEncoder_ByBase32_two_characters() {
	// Encode two characters
	encoder := coding.NewEncoder().FromString("AB").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Two characters encoded:", encoded)
	// Output: Two characters encoded: IFBA====
}

func ExampleEncoder_ByBase32_three_characters() {
	// Encode three characters
	encoder := coding.NewEncoder().FromString("ABC").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Three characters encoded:", encoded)
	// Output: Three characters encoded: IFBEG===
}

func ExampleEncoder_ByBase32_four_characters() {
	// Encode four characters
	encoder := coding.NewEncoder().FromString("ABCD").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Four characters encoded:", encoded)
	// Output: Four characters encoded: IFBEGRA=
}

func ExampleEncoder_ByBase32_five_characters() {
	// Encode five characters
	encoder := coding.NewEncoder().FromString("ABCDE").ByBase32()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Five characters encoded:", encoded)
	// Output: Five characters encoded: IFBEGRCF
}

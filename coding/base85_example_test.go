package coding_test

import (
	"fmt"
	"os"

	"github.com/dromara/dongle/coding"
)

func ExampleEncoder_ByBase85() {
	// Encode a string using base85 (ASCII85 encoding)
	encoder := coding.NewEncoder().FromString("hello world").ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: BOu!rD]j7BEbo7
}

func ExampleDecoder_ByBase85() {
	// Decode a base85 string (ASCII85 encoding)
	decoder := coding.NewDecoder().FromString("BOu!rD]j7BEbo7").ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase85_bytes() {
	// Encode bytes using base85
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: !<N?+"T
}

func ExampleDecoder_ByBase85_bytes() {
	// Decode base85 bytes
	decoder := coding.NewDecoder().FromBytes([]byte("!<N?+\"T")).ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleEncoder_ByBase85_file() {
	// Create a temporary file for demonstration
	content := []byte("hello world")
	tmpFile, err := os.CreateTemp("", "base85_example")
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
	encoder := coding.NewEncoder().FromFile(tmpFile).ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: BOu!rD]j7BEbo7
}

func ExampleDecoder_ByBase85_file() {
	// Create a temporary file with encoded content for demonstration
	encodedContent := []byte("BOu!rD]j7BEbo7")
	tmpFile, err := os.CreateTemp("", "base85_example")
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
	decoder := coding.NewDecoder().FromFile(tmpFile).ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase85_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByBase85_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByBase85_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("A").ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: 5l
}

func ExampleDecoder_ByBase85_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString("5l").ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: A
}

func ExampleEncoder_ByBase85_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase85()
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
	// Encoded: BOu!rD]j7BEbo7
	// Decoded: hello world
	// Round-trip successful: true
}

// Additional examples based on ASCII85 characteristics
func ExampleEncoder_ByBase85_zero_bytes() {
	// Encode zero bytes (ASCII85 uses 'z' for 4 zero bytes)
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Zero bytes encoded:", encoded)
	// Output: Zero bytes encoded: z
}

func ExampleDecoder_ByBase85_zero_bytes() {
	// Decode zero bytes
	decoder := coding.NewDecoder().FromString("z").ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Zero bytes decoded: %v\n", decoded)
	// Output: Zero bytes decoded: [0 0 0 0]
}

func ExampleEncoder_ByBase85_unicode() {
	// Encode unicode string
	encoder := coding.NewEncoder().FromString("Hello, 世界!").ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Unicode encoded:", encoded)
	// Output: Unicode encoded: 87cURD_*$l\<c<CN$/
}

func ExampleDecoder_ByBase85_unicode() {
	// Decode unicode string
	decoder := coding.NewDecoder().FromString("87cURD_*$l\\<c<CN$/").ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Unicode decoded:", decoded)
	// Output: Unicode decoded: Hello, 世界!
}

func ExampleEncoder_ByBase85_large_data() {
	// Encode larger byte array
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}).ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Large data encoded:", encoded)
	// Output: Large data encoded: !<N?+"U52;#mp
}

func ExampleDecoder_ByBase85_large_data() {
	// Decode larger byte array
	decoder := coding.NewDecoder().FromString("!<N?+\"U52;#mp").ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Large data decoded: %v\n", decoded)
	// Output: Large data decoded: [1 2 3 4 5 6 7 8 9 10]
}

func ExampleEncoder_ByBase85_special_characters() {
	// Encode string with special characters
	encoder := coding.NewEncoder().FromString("Hello, @#$%^&*()!").ByBase85()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Special characters encoded:", encoded)
	// Output: Special characters encoded: 87cURD_*"r,:"RA-7UDm+T
}

func ExampleDecoder_ByBase85_special_characters() {
	// Decode string with special characters
	decoder := coding.NewDecoder().FromString("87cURD_*\"r,:\"RA-7UDm+T").ByBase85()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Special characters decoded:", decoded)
	// Output: Special characters decoded: Hello, @#$%^&*()!
}

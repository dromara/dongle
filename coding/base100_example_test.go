package coding_test

import (
	"fmt"
	"os"

	"github.com/dromara/dongle/coding"
)

func ExampleEncoder_ByBase100() {
	// Encode a string using base100
	encoder := coding.NewEncoder().FromString("hello world").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 👟👜👣👣👦🐗👮👦👩👣👛
}

func ExampleDecoder_ByBase100() {
	// Decode a base100 string
	decoder := coding.NewDecoder().FromString("👟👜👣👣👦🐗👮👦👩👣👛").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase100_bytes() {
	// Encode bytes using base100
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 🏸🏹🏺🏻🏼
}

func ExampleDecoder_ByBase100_bytes() {
	// Decode base100 bytes
	decoder := coding.NewDecoder().FromBytes([]byte{240, 159, 143, 184, 240, 159, 143, 185, 240, 159, 143, 186, 240, 159, 143, 187, 240, 159, 143, 188}).ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleEncoder_ByBase100_file() {
	// Create a temporary file for demonstration
	content := []byte("hello world")
	tmpFile, err := os.CreateTemp("", "base100_example")
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
	encoder := coding.NewEncoder().FromFile(tmpFile).ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: 👟👜👣👣👦🐗👮👦👩👣👛
}

func ExampleDecoder_ByBase100_file() {
	// Create a temporary file with encoded content for demonstration
	encodedContent := []byte{240, 159, 145, 159, 240, 159, 145, 156, 240, 159, 145, 163, 240, 159, 145, 163, 240, 159, 145, 166, 240, 159, 144, 151, 240, 159, 145, 174, 240, 159, 145, 166, 240, 159, 145, 169, 240, 159, 145, 163, 240, 159, 145, 155}
	tmpFile, err := os.CreateTemp("", "base100_example")
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
	decoder := coding.NewDecoder().FromFile(tmpFile).ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase100_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByBase100_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByBase100_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("A").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: 🐸
}

func ExampleDecoder_ByBase100_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString("🐸").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: A
}

func ExampleEncoder_ByBase100_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase100()
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
	// Encoded: 👟👜👣👣👦🐗👮👦👩👣👛
	// Decoded: hello world
	// Round-trip successful: true
}

func ExampleEncoder_ByBase100_special_characters() {
	// Encode string with special characters
	encoder := coding.NewEncoder().FromString("Hello, 世界! @#$%^&*()").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Special characters encoded:", encoded)
	// Output: Special characters encoded: 🐿👜👣👣👦🐣🐗📛💯💍📞💌💃🐘🐗🐷🐚🐛🐜👕🐝🐡🐟🐠
}

func ExampleDecoder_ByBase100_special_characters() {
	// Decode string with special characters
	decoder := coding.NewDecoder().FromString("🐿👜👣👣👦🐣🐗📛💯💍📞💌💃🐘🐗🐷🐚🐛🐜👕🐝🐡🐟🐠").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Special characters decoded:", decoded)
	// Output: Special characters decoded: Hello, 世界! @#$%^&*()
}

// Additional examples based on Python verification
func ExampleEncoder_ByBase100_two_characters() {
	// Encode two characters
	encoder := coding.NewEncoder().FromString("AB").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Two characters encoded:", encoded)
	// Output: Two characters encoded: 🐸🐹
}

func ExampleEncoder_ByBase100_three_characters() {
	// Encode three characters
	encoder := coding.NewEncoder().FromString("ABC").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Three characters encoded:", encoded)
	// Output: Three characters encoded: 🐸🐹🐺
}

func ExampleEncoder_ByBase100_four_characters() {
	// Encode four characters
	encoder := coding.NewEncoder().FromString("ABCD").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Four characters encoded:", encoded)
	// Output: Four characters encoded: 🐸🐹🐺🐻
}

func ExampleEncoder_ByBase100_five_characters() {
	// Encode five characters
	encoder := coding.NewEncoder().FromString("ABCDE").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Five characters encoded:", encoded)
	// Output: Five characters encoded: 🐸🐹🐺🐻🐼
}

func ExampleEncoder_ByBase100_zero_bytes() {
	// Encode zero bytes
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Zero bytes encoded:", encoded)
	// Output: Zero bytes encoded: 🏷🏷🏷🏷
}

func ExampleDecoder_ByBase100_zero_bytes() {
	// Decode zero bytes
	decoder := coding.NewDecoder().FromString("🏷🏷🏷🏷").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Zero bytes decoded: %v\n", decoded)
	// Output: Zero bytes decoded: [0 0 0 0]
}

func ExampleEncoder_ByBase100_max_bytes() {
	// Encode max bytes (255, 255, 255, 255)
	encoder := coding.NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Max bytes encoded:", encoded)
	// Output: Max bytes encoded: 📶📶📶📶
}

func ExampleDecoder_ByBase100_max_bytes() {
	// Decode max bytes
	decoder := coding.NewDecoder().FromString("📶📶📶📶").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Max bytes decoded: %v\n", decoded)
	// Output: Max bytes decoded: [255 255 255 255]
}

func ExampleEncoder_ByBase100_large_bytes() {
	// Encode larger byte array
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}).ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Large bytes encoded:", encoded)
	// Output: Large bytes encoded: 🏸🏹🏺🏻🏼🏽🏾🏿🐀🐁
}

func ExampleDecoder_ByBase100_large_bytes() {
	// Decode larger byte array
	decoder := coding.NewDecoder().FromString("🏸🏹🏺🏻🏼🏽🏾🏿🐀🐁").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Large bytes decoded: %v\n", decoded)
	// Output: Large bytes decoded: [1 2 3 4 5 6 7 8 9 10]
}

func ExampleEncoder_ByBase100_unicode() {
	// Encode Unicode string
	encoder := coding.NewEncoder().FromString("你好世界").ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Unicode encoded:", encoded)
	// Output: Unicode encoded: 📛💴💗📜💜💴📛💯💍📞💌💃
}

func ExampleDecoder_ByBase100_unicode() {
	// Decode Unicode string
	decoder := coding.NewDecoder().FromString("📛💴💗📜💜💴📛💯💍📞💌💃").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Unicode decoded:", decoded)
	// Output: Unicode decoded: 你好世界
}

func ExampleEncoder_ByBase100_binary_data() {
	// Encode binary data
	binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC}
	encoder := coding.NewEncoder().FromBytes(binaryData).ByBase100()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Binary data encoded:", encoded)
	// Output: Binary data encoded: 🏷🏸🏹🏺📶📵📴📳
}

func ExampleDecoder_ByBase100_binary_data() {
	// Decode binary data
	decoder := coding.NewDecoder().FromString("🏷🏸🏹🏺📶📵📴📳").ByBase100()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Binary data decoded: %v\n", decoded)
	// Output: Binary data decoded: [0 1 2 3 255 254 253 252]
}

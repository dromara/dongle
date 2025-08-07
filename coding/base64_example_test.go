package coding_test

import (
	"fmt"
	"os"

	"github.com/dromara/dongle/coding"
)

func ExampleEncoder_ByBase64() {
	// Encode a string using standard base64
	encoder := coding.NewEncoder().FromString("hello world").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: aGVsbG8gd29ybGQ=
}

func ExampleDecoder_ByBase64() {
	// Decode a base64 string
	decoder := coding.NewDecoder().FromString("aGVsbG8gd29ybGQ=").ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase64_bytes() {
	// Encode bytes using standard base64
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}).ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: AQIDBAU=
}

func ExampleDecoder_ByBase64_bytes() {
	// Decode base64 bytes
	decoder := coding.NewDecoder().FromBytes([]byte("AQIDBAU=")).ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [1 2 3 4 5]
}

func ExampleEncoder_ByBase64URL() {
	// Encode a string using base64 URL-safe encoding
	encoder := coding.NewEncoder().FromString("https://dongle.go-pkg.com/api/v1/data+test").ByBase64URL()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0
}

func ExampleDecoder_ByBase64URL() {
	// Decode a base64 URL-safe string
	decoder := coding.NewDecoder().FromString("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0").ByBase64URL()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: https://dongle.go-pkg.com/api/v1/data+test
}

func ExampleEncoder_ByBase64URL_bytes() {
	// Encode bytes using base64 URL-safe encoding
	encoder := coding.NewEncoder().FromBytes([]byte("https://dongle.go-pkg.com/api/v1/data+test")).ByBase64URL()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0
}

func ExampleDecoder_ByBase64URL_bytes() {
	// Decode base64 URL-safe bytes
	decoder := coding.NewDecoder().FromBytes([]byte("aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0")).ByBase64URL()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %v\n", decoded)
	// Output: Decoded: [104 116 116 112 115 58 47 47 100 111 110 103 108 101 46 103 111 45 112 107 103 46 99 111 109 47 97 112 105 47 118 49 47 100 97 116 97 43 116 101 115 116]
}

func ExampleEncoder_ByBase64_file() {
	// Create a temporary file for demonstration
	content := []byte("hello world")
	tmpFile, err := os.CreateTemp("", "base64_example")
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
	encoder := coding.NewEncoder().FromFile(tmpFile).ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: aGVsbG8gd29ybGQ=
}

func ExampleDecoder_ByBase64_file() {
	// Create a temporary file with encoded content for demonstration
	encodedContent := []byte("aGVsbG8gd29ybGQ=")
	tmpFile, err := os.CreateTemp("", "base64_example")
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
	decoder := coding.NewDecoder().FromFile(tmpFile).ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello world
}

func ExampleEncoder_ByBase64_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByBase64_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByBase64_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("A").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: QQ==
}

func ExampleDecoder_ByBase64_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString("QQ==").ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: A
}

func ExampleEncoder_ByBase64_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello world"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase64()
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
	// Encoded: aGVsbG8gd29ybGQ=
	// Decoded: hello world
	// Round-trip successful: true
}

func ExampleEncoder_ByBase64URL_round_trip() {
	// Demonstrate round-trip encoding and decoding with URL-safe base64
	url := "https://dongle.go-pkg.com/api/v1/data+test"

	// Encode
	encoder := coding.NewEncoder().FromString(url).ByBase64URL()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByBase64URL()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()

	fmt.Printf("Original: %s\n", url)
	fmt.Printf("Encoded: %s\n", encoded)
	fmt.Printf("Decoded: %s\n", decoded)
	fmt.Printf("Round-trip successful: %t\n", url == decoded)
	// Output:
	// Original: https://dongle.go-pkg.com/api/v1/data+test
	// Encoded: aHR0cHM6Ly9kb25nbGUuZ28tcGtnLmNvbS9hcGkvdjEvZGF0YSt0ZXN0
	// Decoded: https://dongle.go-pkg.com/api/v1/data+test
	// Round-trip successful: true
}

func ExampleEncoder_ByBase64_special_characters() {
	// Encode string with special characters
	encoder := coding.NewEncoder().FromString("Hello, 世界! @#$%^&*()").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Special characters encoded:", encoded)
	// Output: Special characters encoded: SGVsbG8sIOS4lueVjCEgQCMkJV4mKigp
}

func ExampleDecoder_ByBase64_special_characters() {
	// Decode string with special characters
	decoder := coding.NewDecoder().FromString("SGVsbG8sIOS4lueVjCEgQCMkJV4mKigp").ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Special characters decoded:", decoded)
	// Output: Special characters decoded: Hello, 世界! @#$%^&*()
}

// Additional examples based on Python verification
func ExampleEncoder_ByBase64_two_characters() {
	// Encode two characters
	encoder := coding.NewEncoder().FromString("AB").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Two characters encoded:", encoded)
	// Output: Two characters encoded: QUI=
}

func ExampleEncoder_ByBase64_three_characters() {
	// Encode three characters
	encoder := coding.NewEncoder().FromString("ABC").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Three characters encoded:", encoded)
	// Output: Three characters encoded: QUJD
}

func ExampleEncoder_ByBase64_four_characters() {
	// Encode four characters
	encoder := coding.NewEncoder().FromString("ABCD").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Four characters encoded:", encoded)
	// Output: Four characters encoded: QUJDRA==
}

func ExampleEncoder_ByBase64_five_characters() {
	// Encode five characters
	encoder := coding.NewEncoder().FromString("ABCDE").ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Five characters encoded:", encoded)
	// Output: Five characters encoded: QUJDREU=
}

func ExampleEncoder_ByBase64_zero_bytes() {
	// Encode zero bytes
	encoder := coding.NewEncoder().FromBytes([]byte{0x00, 0x00, 0x00, 0x00}).ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Zero bytes encoded:", encoded)
	// Output: Zero bytes encoded: AAAAAA==
}

func ExampleDecoder_ByBase64_zero_bytes() {
	// Decode zero bytes
	decoder := coding.NewDecoder().FromString("AAAAAA==").ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Zero bytes decoded: %v\n", decoded)
	// Output: Zero bytes decoded: [0 0 0 0]
}

func ExampleEncoder_ByBase64_max_bytes() {
	// Encode max bytes (255, 255, 255, 255)
	encoder := coding.NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Max bytes encoded:", encoded)
	// Output: Max bytes encoded: /////w==
}

func ExampleDecoder_ByBase64_max_bytes() {
	// Decode max bytes
	decoder := coding.NewDecoder().FromString("/////w==").ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Max bytes decoded: %v\n", decoded)
	// Output: Max bytes decoded: [255 255 255 255]
}

func ExampleEncoder_ByBase64URL_max_bytes() {
	// Encode max bytes using URL-safe base64
	encoder := coding.NewEncoder().FromBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}).ByBase64URL()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Max bytes URL-safe encoded:", encoded)
	// Output: Max bytes URL-safe encoded: _____w==
}

func ExampleDecoder_ByBase64URL_max_bytes() {
	// Decode max bytes using URL-safe base64
	decoder := coding.NewDecoder().FromString("_____w==").ByBase64URL()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Max bytes URL-safe decoded: %v\n", decoded)
	// Output: Max bytes URL-safe decoded: [255 255 255 255]
}

func ExampleEncoder_ByBase64_large_bytes() {
	// Encode larger byte array
	encoder := coding.NewEncoder().FromBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}).ByBase64()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Large bytes encoded:", encoded)
	// Output: Large bytes encoded: AQIDBAUGBwgJCg==
}

func ExampleDecoder_ByBase64_large_bytes() {
	// Decode larger byte array
	decoder := coding.NewDecoder().FromString("AQIDBAUGBwgJCg==").ByBase64()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Large bytes decoded: %v\n", decoded)
	// Output: Large bytes decoded: [1 2 3 4 5 6 7 8 9 10]
}

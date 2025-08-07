package coding_test

import (
	"fmt"

	"github.com/dromara/dongle/coding"
	"github.com/dromara/dongle/mock"
)

func ExampleEncoder_ByMorse() {
	// Encode a string using morse code
	encoder := coding.NewEncoder().FromString("hello").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: .... . .-.. .-.. ---
}

func ExampleDecoder_ByMorse() {
	// Decode a morse code string
	decoder := coding.NewDecoder().FromString(".... . .-.. .-.. ---").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello
}

func ExampleEncoder_ByMorse_bytes() {
	// Encode bytes using morse code
	encoder := coding.NewEncoder().FromBytes([]byte("abc")).ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: .- -... -.-.
}

func ExampleDecoder_ByMorse_bytes() {
	// Decode morse code bytes
	decoder := coding.NewDecoder().FromBytes([]byte(".- -... -.-.")).ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToBytes()
	fmt.Printf("Decoded: %s\n", decoded)
	// Output: Decoded: abc
}

func ExampleEncoder_ByMorse_file() {
	// Create a mock file for demonstration
	content := []byte("hello")
	file := mock.NewFile(content, "morse_example.txt")

	// Encode from file
	encoder := coding.NewEncoder().FromFile(file).ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encoded: .... . .-.. .-.. ---
}

func ExampleDecoder_ByMorse_file() {
	// Create a mock file with encoded content for demonstration
	encodedContent := []byte(".... . .-.. .-.. ---")
	file := mock.NewFile(encodedContent, "morse_example.txt")

	// Decode from file
	decoder := coding.NewDecoder().FromFile(file).ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decoded: hello
}

func ExampleEncoder_ByMorse_empty() {
	// Encode empty string
	encoder := coding.NewEncoder().FromString("").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Printf("Empty encoded: '%s'\n", encoded)
	// Output: Empty encoded: ''
}

func ExampleDecoder_ByMorse_empty() {
	// Decode empty string
	decoder := coding.NewDecoder().FromString("").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Printf("Empty decoded: '%s'\n", decoded)
	// Output: Empty decoded: ''
}

func ExampleEncoder_ByMorse_single_character() {
	// Encode single character
	encoder := coding.NewEncoder().FromString("a").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Single character encoded:", encoded)
	// Output: Single character encoded: .-
}

func ExampleDecoder_ByMorse_single_character() {
	// Decode single character
	decoder := coding.NewDecoder().FromString(".-").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Single character decoded:", decoded)
	// Output: Single character decoded: a
}

func ExampleEncoder_ByMorse_round_trip() {
	// Demonstrate round-trip encoding and decoding
	original := "hello"

	// Encode
	encoder := coding.NewEncoder().FromString(original).ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()

	// Decode
	decoder := coding.NewDecoder().FromString(encoded).ByMorse()
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
	// Original: hello
	// Encoded: .... . .-.. .-.. ---
	// Decoded: hello
	// Round-trip successful: true
}

func ExampleEncoder_ByMorse_numbers() {
	// Encode string with numbers
	encoder := coding.NewEncoder().FromString("123").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Numbers encoded:", encoded)
	// Output: Numbers encoded: .---- ..--- ...--
}

func ExampleDecoder_ByMorse_numbers() {
	// Decode string with numbers
	decoder := coding.NewDecoder().FromString(".---- ..--- ...--").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Numbers decoded:", decoded)
	// Output: Numbers decoded: 123
}

func ExampleEncoder_ByMorse_punctuation() {
	// Encode string with punctuation
	encoder := coding.NewEncoder().FromString("!?").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Punctuation encoded:", encoded)
	// Output: Punctuation encoded: -.-.-- ..--..
}

func ExampleDecoder_ByMorse_punctuation() {
	// Decode string with punctuation
	decoder := coding.NewDecoder().FromString("-.-.-- ..--..").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Punctuation decoded:", decoded)
	// Output: Punctuation decoded: !?
}

func ExampleEncoder_ByMorse_mixed_characters() {
	// Encode string with mixed characters
	encoder := coding.NewEncoder().FromString("a1!").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Mixed characters encoded:", encoded)
	// Output: Mixed characters encoded: .- .---- -.-.--
}

func ExampleDecoder_ByMorse_mixed_characters() {
	// Decode string with mixed characters
	decoder := coding.NewDecoder().FromString(".- .---- -.-.--").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Mixed characters decoded:", decoded)
	// Output: Mixed characters decoded: a1!
}

func ExampleEncoder_ByMorse_all_letters() {
	// Encode all letters
	encoder := coding.NewEncoder().FromString("abcdefghijklmnopqrstuvwxyz").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("All letters encoded:", encoded)
	// Output: All letters encoded: .- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --..
}

func ExampleDecoder_ByMorse_all_letters() {
	// Decode all letters
	decoder := coding.NewDecoder().FromString(".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --..").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("All letters decoded:", decoded)
	// Output: All letters decoded: abcdefghijklmnopqrstuvwxyz
}

func ExampleEncoder_ByMorse_all_numbers() {
	// Encode all numbers
	encoder := coding.NewEncoder().FromString("0123456789").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("All numbers encoded:", encoded)
	// Output: All numbers encoded: ----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.
}

func ExampleDecoder_ByMorse_all_numbers() {
	// Decode all numbers
	decoder := coding.NewDecoder().FromString("----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("All numbers decoded:", decoded)
	// Output: All numbers decoded: 0123456789
}

func ExampleEncoder_ByMorse_unknown_characters() {
	// Encode string with unknown characters (should skip them)
	encoder := coding.NewEncoder().FromString("hello@world").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Unknown characters encoded:", encoded)
	// Output: Unknown characters encoded: .... . .-.. .-.. --- .-- --- .-. .-.. -..
}

func ExampleEncoder_ByMorse_space_error() {
	// Encode string with spaces (should return error)
	encoder := coding.NewEncoder().FromString("hello world").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Encoded:", encoded)
	// Output: Encode error: coding/morse: input cannot contain spaces
}

func ExampleDecoder_ByMorse_invalid_character() {
	// Decode invalid morse code
	decoder := coding.NewDecoder().FromString(".... . .-.. .-.. --- INVALID").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Decoded:", decoded)
	// Output: Decode error: coding/morse: unknown character INVALID
}

func ExampleEncoder_ByMorse_large_data() {
	// Encode large data
	largeData := "hello"
	encoder := coding.NewEncoder().FromString(largeData).ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Large data encoded:", encoded)
	// Output: Large data encoded: .... . .-.. .-.. ---
}

func ExampleDecoder_ByMorse_large_data() {
	// Decode large data
	decoder := coding.NewDecoder().FromString(".... . .-.. .-.. ---").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Large data decoded:", decoded)
	// Output: Large data decoded: hello
}

func ExampleEncoder_ByMorse_special_morse_codes() {
	// Encode special morse codes
	encoder := coding.NewEncoder().FromString("SOS").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("SOS encoded:", encoded)
	// Output: SOS encoded: ... --- ...
}

func ExampleDecoder_ByMorse_special_morse_codes() {
	// Decode special morse codes
	decoder := coding.NewDecoder().FromString("... --- ...").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("SOS decoded:", decoded)
	// Output: SOS decoded: sos
}

func ExampleEncoder_ByMorse_case_insensitive() {
	// Encode uppercase string (should be converted to lowercase)
	encoder := coding.NewEncoder().FromString("HELLO").ByMorse()
	if encoder.Error != nil {
		fmt.Println("Encode error:", encoder.Error)
		return
	}
	encoded := encoder.ToString()
	fmt.Println("Uppercase encoded:", encoded)
	// Output: Uppercase encoded: .... . .-.. .-.. ---
}

func ExampleDecoder_ByMorse_case_insensitive() {
	// Decode morse code (result should be lowercase)
	decoder := coding.NewDecoder().FromString(".... . .-.. .-.. ---").ByMorse()
	if decoder.Error != nil {
		fmt.Println("Decode error:", decoder.Error)
		return
	}
	decoded := decoder.ToString()
	fmt.Println("Morse decoded (lowercase):", decoded)
	// Output: Morse decoded (lowercase): hello
}

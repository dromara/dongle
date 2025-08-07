package hash_test

import (
	"fmt"

	"github.com/dromara/dongle/hash"
	"github.com/dromara/dongle/mock"
)

func ExampleHasher_ByRipemd160() {
	// Hash a string using RIPEMD160
	hasher := hash.NewHasher().FromString("hello").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: 108f07b8382412612c048d07d13f814118445acd
}

func ExampleHasher_ByRipemd160_bytes() {
	// Hash bytes using RIPEMD160
	hasher := hash.NewHasher().FromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}).ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: cd2e472470be8fd70a306daec5c59f485ea43929
}

func ExampleHasher_ByRipemd160_file() {
	// Create a mock file for testing
	content := "hello world"
	file := mock.NewFile([]byte(content), "ripemd160_test.txt")

	// Hash file using RIPEMD160
	hasher := hash.NewHasher().FromFile(file).ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: 98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f
}

func ExampleHasher_ByRipemd160_empty() {
	// Hash empty string using RIPEMD160
	hasher := hash.NewHasher().FromString("").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash:
}

func ExampleHasher_ByRipemd160_single_character() {
	// Hash single character using RIPEMD160
	hasher := hash.NewHasher().FromString("a").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: 0bdc9d2d256b3ee9daae347be6f4dc835a467ffe
}

func ExampleHasher_ByRipemd160_unicode() {
	// Hash Unicode string using RIPEMD160
	hasher := hash.NewHasher().FromString("你好世界").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: 93d2c5a73ddad1b1223d8c6667c54ceebd70b0e9
}

func ExampleHasher_ByRipemd160_digits() {
	// Hash digits using RIPEMD160
	hasher := hash.NewHasher().FromString("1234567890").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: 9d752daa3fb4df29837088e1e5a1acf74932e074
}

func ExampleHasher_ByRipemd160_alphabet() {
	// Hash alphabet using RIPEMD160
	hasher := hash.NewHasher().FromString("abcdefghijklmnopqrstuvwxyz").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: f71c27109c692c1b56bbdceb5b9d2865b3708dbc
}

func ExampleHasher_ByRipemd160_alphanumeric() {
	// Hash alphanumeric string using RIPEMD160
	hasher := hash.NewHasher().FromString("abc123def456").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: 2c983c7060d3ac797d42153d86fc59a4a5fc389f
}

func ExampleHasher_ByRipemd160_quick_brown_fox() {
	// Hash "The quick brown fox jumps over the lazy dog" using RIPEMD160
	hasher := hash.NewHasher().FromString("The quick brown fox jumps over the lazy dog").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: 37f332f68db77bd9d7edd4969571ad671cf9dd3b
}

func ExampleHasher_ByRipemd160_large_data() {
	// Hash large data using RIPEMD160
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = 'a'
	}
	hasher := hash.NewHasher().FromBytes(largeData).ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("RIPEMD160 hash:", hashValue)
	// Output: RIPEMD160 hash: aa69deee9a8922e92f8105e007f76110f381e9cf
}

func ExampleHasher_ByRipemd160_base64_output() {
	// Hash string and output as base64
	hasher := hash.NewHasher().FromString("hello").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToBase64String()
	fmt.Println("RIPEMD160 hash (base64):", hashValue)
	// Output: RIPEMD160 hash (base64): EI8HuDgkEmEsBI0H0T+BQRhEWs0=
}

func ExampleHasher_ByRipemd160_raw_bytes() {
	// Hash string and get raw bytes
	hasher := hash.NewHasher().FromString("hello").ByRipemd160()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashBytes := hasher.ToRawBytes()
	fmt.Printf("RIPEMD160 hash (bytes): %v\n", hashBytes)
	// Output: RIPEMD160 hash (bytes): [16 143 7 184 56 36 18 97 44 4 141 7 209 63 129 65 24 68 90 205]
}

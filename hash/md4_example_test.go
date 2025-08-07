package hash_test

import (
	"fmt"

	"github.com/dromara/dongle/hash"
	"github.com/dromara/dongle/mock"
)

func ExampleHasher_ByMd4() {
	// Hash a string using MD4
	hasher := hash.NewHasher().FromString("hello").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: 866437cb7a794bce2b727acc0362ee27
}

func ExampleHasher_ByMd4_bytes() {
	// Hash bytes using MD4
	hasher := hash.NewHasher().FromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}).ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: aec6b48c10659e3d6e18a2cde8f8d3a0
}

func ExampleHasher_ByMd4_file() {
	// Create a mock file for testing
	content := "hello world"
	file := mock.NewFile([]byte(content), "md4_test.txt")

	// Hash file using MD4
	hasher := hash.NewHasher().FromFile(file).ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: aa010fbc1d14c795d86ef98c95479d17
}

func ExampleHasher_ByMd4_empty() {
	// Hash empty string using MD4
	hasher := hash.NewHasher().FromString("").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash:
}

func ExampleHasher_ByMd4_single_character() {
	// Hash single character using MD4
	hasher := hash.NewHasher().FromString("a").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: bde52cb31de33e46245e05fbdbd6fb24
}

func ExampleHasher_ByMd4_unicode() {
	// Hash Unicode string using MD4
	hasher := hash.NewHasher().FromString("你好世界").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: b7d2daccdcc3ab0a91110b5c31e98ab1
}

func ExampleHasher_ByMd4_digits() {
	// Hash digits using MD4
	hasher := hash.NewHasher().FromString("1234567890").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: 85b196c3e39457d91cab9c905f9a11c0
}

func ExampleHasher_ByMd4_alphabet() {
	// Hash alphabet using MD4
	hasher := hash.NewHasher().FromString("abcdefghijklmnopqrstuvwxyz").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: d79e1c308aa5bbcdeea8ed63df412da9
}

func ExampleHasher_ByMd4_alphanumeric() {
	// Hash alphanumeric string using MD4
	hasher := hash.NewHasher().FromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: 043f8582f241db351ce627e153e7f0e4
}

func ExampleHasher_ByMd4_quick_brown_fox() {
	// Hash "The quick brown fox jumps over the lazy dog" using MD4
	hasher := hash.NewHasher().FromString("The quick brown fox jumps over the lazy dog").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: 1bee69a46ba811185c194762abaeae90
}

func ExampleHasher_ByMd4_large_data() {
	// Hash large data using MD4
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = 'a'
	}
	hasher := hash.NewHasher().FromBytes(largeData).ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD4 hash:", hashValue)
	// Output: MD4 hash: 5f1bf26a8067c9159b91f1440f7c9e8a
}

func ExampleHasher_ByMd4_base64_output() {
	// Hash string and output as base64
	hasher := hash.NewHasher().FromString("hello").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToBase64String()
	fmt.Println("MD4 hash (base64):", hashValue)
	// Output: MD4 hash (base64): hmQ3y3p5S84rcnrMA2LuJw==
}

func ExampleHasher_ByMd4_raw_bytes() {
	// Hash string and get raw bytes
	hasher := hash.NewHasher().FromString("hello").ByMd4()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashBytes := hasher.ToRawBytes()
	fmt.Printf("MD4 hash (bytes): %v\n", hashBytes)
	// Output: MD4 hash (bytes): [134 100 55 203 122 121 75 206 43 114 122 204 3 98 238 39]
}

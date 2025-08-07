package hash_test

import (
	"fmt"

	"github.com/dromara/dongle/hash"
	"github.com/dromara/dongle/mock"
)

func ExampleHasher_ByMd5() {
	// Hash a string using MD5
	hasher := hash.NewHasher().FromString("hello").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: 5d41402abc4b2a76b9719d911017c592
}

func ExampleHasher_ByMd5_bytes() {
	// Hash bytes using MD5
	hasher := hash.NewHasher().FromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}).ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: c56bd5480f6e5413cb62a0ad9666613a
}

func ExampleHasher_ByMd5_file() {
	// Create a mock file for testing
	content := "hello world"
	file := mock.NewFile([]byte(content), "md5_test.txt")

	// Hash file using MD5
	hasher := hash.NewHasher().FromFile(file).ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: 5eb63bbbe01eeed093cb22bb8f5acdc3
}

func ExampleHasher_ByMd5_empty() {
	// Hash empty string using MD5
	hasher := hash.NewHasher().FromString("").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash:
}

func ExampleHasher_ByMd5_single_character() {
	// Hash single character using MD5
	hasher := hash.NewHasher().FromString("a").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: 0cc175b9c0f1b6a831c399e269772661
}

func ExampleHasher_ByMd5_unicode() {
	// Hash Unicode string using MD5
	hasher := hash.NewHasher().FromString("你好世界").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: 65396ee4aad0b4f17aacd1c6112ee364
}

func ExampleHasher_ByMd5_digits() {
	// Hash digits using MD5
	hasher := hash.NewHasher().FromString("1234567890").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: e807f1fcf82d132f9bb018ca6738a19f
}

func ExampleHasher_ByMd5_alphabet() {
	// Hash alphabet using MD5
	hasher := hash.NewHasher().FromString("abcdefghijklmnopqrstuvwxyz").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: c3fcd3d76192e4007dfb496cca67e13b
}

func ExampleHasher_ByMd5_alphanumeric() {
	// Hash alphanumeric string using MD5
	hasher := hash.NewHasher().FromString("abc123def456").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: 30cb73276df970492b1148cc0e3f23a7
}

func ExampleHasher_ByMd5_quick_brown_fox() {
	// Hash "The quick brown fox jumps over the lazy dog" using MD5
	hasher := hash.NewHasher().FromString("The quick brown fox jumps over the lazy dog").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: 9e107d9d372bb6826bd81d3542a419d6
}

func ExampleHasher_ByMd5_large_data() {
	// Hash large data using MD5
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = 'a'
	}
	hasher := hash.NewHasher().FromBytes(largeData).ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD5 hash:", hashValue)
	// Output: MD5 hash: cabe45dcc9ae5b66ba86600cca6b8ba8
}

func ExampleHasher_ByMd5_base64_output() {
	// Hash string and output as base64
	hasher := hash.NewHasher().FromString("hello").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToBase64String()
	fmt.Println("MD5 hash (base64):", hashValue)
	// Output: MD5 hash (base64): XUFAKrxLKna5cZ2REBfFkg==
}

func ExampleHasher_ByMd5_raw_bytes() {
	// Hash string and get raw bytes
	hasher := hash.NewHasher().FromString("hello").ByMd5()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashBytes := hasher.ToRawBytes()
	fmt.Printf("MD5 hash (bytes): %v\n", hashBytes)
	// Output: MD5 hash (bytes): [93 65 64 42 188 75 42 118 185 113 157 145 16 23 197 146]
}

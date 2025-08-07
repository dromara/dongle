package hash_test

import (
	"fmt"

	"github.com/dromara/dongle/hash"
	"github.com/dromara/dongle/mock"
)

func ExampleHasher_BySha1() {
	// Hash a string using SHA1
	hasher := hash.NewHasher().FromString("hello").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
}

func ExampleHasher_BySha1_bytes() {
	// Hash bytes using SHA1
	hasher := hash.NewHasher().FromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}).BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 494179714a6cd627239dfededf2de9ef994caf03
}

func ExampleHasher_BySha1_file() {
	// Create a mock file for testing
	content := "hello world"
	file := mock.NewFile([]byte(content), "sha1_test.txt")

	// Hash file using SHA1
	hasher := hash.NewHasher().FromFile(file).BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
}

func ExampleHasher_BySha1_empty() {
	// Hash empty string using SHA1
	hasher := hash.NewHasher().FromString("").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash:
}

func ExampleHasher_BySha1_single_character() {
	// Hash single character using SHA1
	hasher := hash.NewHasher().FromString("a").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
}

func ExampleHasher_BySha1_unicode() {
	// Hash Unicode string using SHA1
	hasher := hash.NewHasher().FromString("你好世界").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: dabaa5fe7c47fb21be902480a13013f16a1ab6eb
}

func ExampleHasher_BySha1_digits() {
	// Hash digits using SHA1
	hasher := hash.NewHasher().FromString("1234567890").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 01b307acba4f54f55aafc33bb06bbbf6ca803e9a
}

func ExampleHasher_BySha1_alphabet() {
	// Hash alphabet using SHA1
	hasher := hash.NewHasher().FromString("abcdefghijklmnopqrstuvwxyz").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 32d10c7b8cf96570ca04ce37f2a19d84240d3a89
}

func ExampleHasher_BySha1_alphanumeric() {
	// Hash alphanumeric string using SHA1
	hasher := hash.NewHasher().FromString("abc123def456").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 90bd1b48e958257948487b90bee080ba5ed00caa
}

func ExampleHasher_BySha1_quick_brown_fox() {
	// Hash "The quick brown fox jumps over the lazy dog" using SHA1
	hasher := hash.NewHasher().FromString("The quick brown fox jumps over the lazy dog").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
}

func ExampleHasher_BySha1_large_data() {
	// Hash large data using SHA1
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = 'a'
	}
	hasher := hash.NewHasher().FromBytes(largeData).BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA1 hash:", hashValue)
	// Output: SHA1 hash: 291e9a6c66994949b57ba5e650361e98fc36b1ba
}

func ExampleHasher_BySha1_base64_output() {
	// Hash string and output as base64
	hasher := hash.NewHasher().FromString("hello").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToBase64String()
	fmt.Println("SHA1 hash (base64):", hashValue)
	// Output: SHA1 hash (base64): qvTGHdzF6KLavt4PO0gs2a6pQ00=
}

func ExampleHasher_BySha1_raw_bytes() {
	// Hash string and get raw bytes
	hasher := hash.NewHasher().FromString("hello").BySha1()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashBytes := hasher.ToRawBytes()
	fmt.Printf("SHA1 hash (bytes): %v\n", hashBytes)
	// Output: SHA1 hash (bytes): [170 244 198 29 220 197 232 162 218 190 222 15 59 72 44 217 174 169 67 77]
}

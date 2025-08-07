package hash_test

import (
	"fmt"

	"github.com/dromara/dongle/hash"
	"github.com/dromara/dongle/mock"
)

func ExampleHasher_ByMd2() {
	// Hash a string using MD2
	hasher := hash.NewHasher().FromString("hello").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: a9046c73e00331af68917d3804f70655
}

func ExampleHasher_ByMd2_bytes() {
	// Hash bytes using MD2
	hasher := hash.NewHasher().FromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}).ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: 06db4c310570268754114f747e1f0946
}

func ExampleHasher_ByMd2_file() {
	// Create a mock file for testing
	content := "hello world"
	file := mock.NewFile([]byte(content), "md2_test.txt")

	// Hash file using MD2
	hasher := hash.NewHasher().FromFile(file).ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: d9cce882ee690a5c1ce70beff3a78c77
}

func ExampleHasher_ByMd2_empty() {
	// Hash empty string using MD2
	hasher := hash.NewHasher().FromString("").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash:
}

func ExampleHasher_ByMd2_single_character() {
	// Hash single character using MD2
	hasher := hash.NewHasher().FromString("a").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: 32ec01ec4a6dac72c0ab96fb34c0b5d1
}

func ExampleHasher_ByMd2_unicode() {
	// Hash Unicode string using MD2
	hasher := hash.NewHasher().FromString("你好世界").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: ffe1e23ea9a918eebc68a8f1e0b91758
}

func ExampleHasher_ByMd2_digits() {
	// Hash digits using MD2
	hasher := hash.NewHasher().FromString("1234567890").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: 38e53522a2e67fc5ea57bae1575a3107
}

func ExampleHasher_ByMd2_alphabet() {
	// Hash alphabet using MD2
	hasher := hash.NewHasher().FromString("abcdefghijklmnopqrstuvwxyz").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: 4e8ddff3650292ab5a4108c3aa47940b
}

func ExampleHasher_ByMd2_alphanumeric() {
	// Hash alphanumeric string using MD2
	hasher := hash.NewHasher().FromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: da33def2a42df13975352846c30338cd
}

func ExampleHasher_ByMd2_quick_brown_fox() {
	// Hash "The quick brown fox jumps over the lazy dog" using MD2
	hasher := hash.NewHasher().FromString("The quick brown fox jumps over the lazy dog").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: 03d85a0d629d2c442e987525319fc471
}

func ExampleHasher_ByMd2_large_data() {
	// Hash large data using MD2
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = 'a'
	}
	hasher := hash.NewHasher().FromBytes(largeData).ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("MD2 hash:", hashValue)
	// Output: MD2 hash: dd21a412ef3f285fd1f2e70a6c10a702
}

func ExampleHasher_ByMd2_base64_output() {
	// Hash string and output as base64
	hasher := hash.NewHasher().FromString("hello").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToBase64String()
	fmt.Println("MD2 hash (base64):", hashValue)
	// Output: MD2 hash (base64): qQRsc+ADMa9okX04BPcGVQ==
}

func ExampleHasher_ByMd2_raw_bytes() {
	// Hash string and get raw bytes
	hasher := hash.NewHasher().FromString("hello").ByMd2()
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashBytes := hasher.ToRawBytes()
	fmt.Printf("MD2 hash (bytes): %v\n", hashBytes)
	// Output: MD2 hash (bytes): [169 4 108 115 224 3 49 175 104 145 125 56 4 247 6 85]
}

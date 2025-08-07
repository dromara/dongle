package hash_test

import (
	"fmt"

	"github.com/dromara/dongle/hash"
	"github.com/dromara/dongle/mock"
)

func ExampleHasher_BySha3_sha224() {
	// Hash a string using SHA3-224
	hasher := hash.NewHasher().FromString("hello").BySha3(224)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-224 hash:", hashValue)
	// Output: SHA3-224 hash: b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81
}

func ExampleHasher_BySha3_sha256() {
	// Hash a string using SHA3-256
	hasher := hash.NewHasher().FromString("hello").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392
}

func ExampleHasher_BySha3_sha384() {
	// Hash a string using SHA3-384
	hasher := hash.NewHasher().FromString("hello").BySha3(384)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-384 hash:", hashValue)
	// Output: SHA3-384 hash: 720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887
}

func ExampleHasher_BySha3_sha512() {
	// Hash a string using SHA3-512
	hasher := hash.NewHasher().FromString("hello").BySha3(512)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-512 hash:", hashValue)
	// Output: SHA3-512 hash: 75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976
}

func ExampleHasher_BySha3_bytes() {
	// Hash bytes using SHA3-256
	hasher := hash.NewHasher().FromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}).BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 605a0514059192e26dbf06cfab86f3e9bbb9a69363d4be925b2246dcd8659a95
}

func ExampleHasher_BySha3_file() {
	// Create a mock file for testing
	content := "hello world"
	file := mock.NewFile([]byte(content), "sha3_test.txt")

	// Hash file using SHA3-256
	hasher := hash.NewHasher().FromFile(file).BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938
}

func ExampleHasher_BySha3_empty() {
	// Hash empty string using SHA3-256
	hasher := hash.NewHasher().FromString("").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash:
}

func ExampleHasher_BySha3_single_character() {
	// Hash single character using SHA3-256
	hasher := hash.NewHasher().FromString("a").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b
}

func ExampleHasher_BySha3_unicode() {
	// Hash Unicode string using SHA3-256
	hasher := hash.NewHasher().FromString("你好世界").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 2fa8285e74d1fe23f5eddd839ae398832d5470e19956027a6b9ccc1bf4b2b21a
}

func ExampleHasher_BySha3_digits() {
	// Hash digits using SHA3-256
	hasher := hash.NewHasher().FromString("1234567890").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 01da8843e976913aa5c15a62d45f1c9267391dcbd0a76ad411919043f374a163
}

func ExampleHasher_BySha3_alphabet() {
	// Hash alphabet using SHA3-256
	hasher := hash.NewHasher().FromString("abcdefghijklmnopqrstuvwxyz").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521
}

func ExampleHasher_BySha3_alphanumeric() {
	// Hash alphanumeric string using SHA3-256
	hasher := hash.NewHasher().FromString("abc123def456").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: cca6a80ee92bf9c8f762f3a47f03fa70c2ade9393aa377ac83535b315338ee86
}

func ExampleHasher_BySha3_quick_brown_fox() {
	// Hash "The quick brown fox jumps over the lazy dog" using SHA3-256
	hasher := hash.NewHasher().FromString("The quick brown fox jumps over the lazy dog").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04
}

func ExampleHasher_BySha3_large_data() {
	// Hash large data using SHA3-256
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = 'a'
	}
	hasher := hash.NewHasher().FromBytes(largeData).BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA3-256 hash:", hashValue)
	// Output: SHA3-256 hash: 8f3934e6f7a15698fe0f396b95d8c4440929a8fa6eae140171c068b4549fbf81
}

func ExampleHasher_BySha3_base64_output() {
	// Hash string and output as base64
	hasher := hash.NewHasher().FromString("hello").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToBase64String()
	fmt.Println("SHA3-256 hash (base64):", hashValue)
	// Output: SHA3-256 hash (base64): Mzi+aU9QxfM4gUmGzfBoZFOoiLhPQk15KvS5ICOY85I=
}

func ExampleHasher_BySha3_raw_bytes() {
	// Hash string and get raw bytes
	hasher := hash.NewHasher().FromString("hello").BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashBytes := hasher.ToRawBytes()
	fmt.Printf("SHA3-256 hash (bytes): %v\n", hashBytes)
	// Output: SHA3-256 hash (bytes): [51 56 190 105 79 80 197 243 56 129 73 134 205 240 104 100 83 168 136 184 79 66 77 121 42 244 185 32 35 152 243 146]
}

func ExampleHasher_BySha3_all_sizes() {
	// Hash string using all SHA3 sizes
	data := "hello"
	sizes := []int{224, 256, 384, 512}

	for _, size := range sizes {
		hasher := hash.NewHasher().FromString(data).BySha3(size)
		if hasher.Error != nil {
			fmt.Printf("SHA3-%d error: %v\n", size, hasher.Error)
			continue
		}
		hashValue := hasher.ToHexString()
		fmt.Printf("SHA3-%d: %s\n", size, hashValue)
	}
	// Output: SHA3-224: b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81
	// SHA3-256: 3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392
	// SHA3-384: 720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887
	// SHA3-512: 75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976
}

func ExampleHasher_BySha3_hmac() {
	// Hash string with HMAC using SHA3-256
	hasher := hash.NewHasher().FromString("hello").WithKey([]byte("secret")).BySha3(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("HMAC-SHA3-256 hash:", hashValue)
	// Output: HMAC-SHA3-256 hash: 850ae61707b3e60d4e45548c4facfda415d301712641fd11535cf395d9e2d7fe
}

func ExampleHasher_BySha3_hmac_all_sizes() {
	// Hash string with HMAC using all SHA3 sizes
	data := "hello"
	key := []byte("secret")
	sizes := []int{224, 256, 384, 512}

	for _, size := range sizes {
		hasher := hash.NewHasher().FromString(data).WithKey(key).BySha3(size)
		if hasher.Error != nil {
			fmt.Printf("HMAC-SHA3-%d error: %v\n", size, hasher.Error)
			continue
		}
		hashValue := hasher.ToHexString()
		fmt.Printf("HMAC-SHA3-%d: %s\n", size, hashValue)
	}
	// Output: HMAC-SHA3-224: d078791e9bf080c2139f883ac65033d4b5b75bbdb4088c494d0b6a14
	// HMAC-SHA3-256: 850ae61707b3e60d4e45548c4facfda415d301712641fd11535cf395d9e2d7fe
	// HMAC-SHA3-384: e24e0dc664132644a6740071af5a05622edffea8afacf0a4060111961bc9148f23c001b6f7d7e79a44b9896b1f00cd85
	// HMAC-SHA3-512: bc07c2dfc0295b420662bda474eb8db11b0389822e13da56cf9991f467f2f6c713c481aa8663900ecaee310bf2f226eaa5c2d1345dfebee990658bd529a9c504
}

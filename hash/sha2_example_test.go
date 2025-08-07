package hash_test

import (
	"fmt"

	"github.com/dromara/dongle/hash"
	"github.com/dromara/dongle/mock"
)

func ExampleHasher_BySha2_sha224() {
	// Hash a string using SHA2-224
	hasher := hash.NewHasher().FromString("hello").BySha2(224)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-224 hash:", hashValue)
	// Output: SHA2-224 hash: ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193
}

func ExampleHasher_BySha2_sha256() {
	// Hash a string using SHA2-256
	hasher := hash.NewHasher().FromString("hello").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
}

func ExampleHasher_BySha2_sha384() {
	// Hash a string using SHA2-384
	hasher := hash.NewHasher().FromString("hello").BySha2(384)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-384 hash:", hashValue)
	// Output: SHA2-384 hash: 59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f
}

func ExampleHasher_BySha2_sha512() {
	// Hash a string using SHA2-512
	hasher := hash.NewHasher().FromString("hello").BySha2(512)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-512 hash:", hashValue)
	// Output: SHA2-512 hash: 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
}

func ExampleHasher_BySha2_bytes() {
	// Hash bytes using SHA2-256
	hasher := hash.NewHasher().FromBytes([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}).BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: 1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab3
}

func ExampleHasher_BySha2_file() {
	// Create a mock file for testing
	content := "hello world"
	file := mock.NewFile([]byte(content), "sha2_test.txt")

	// Hash file using SHA2-256
	hasher := hash.NewHasher().FromFile(file).BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
}

func ExampleHasher_BySha2_empty() {
	// Hash empty string using SHA2-256
	hasher := hash.NewHasher().FromString("").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash:
}

func ExampleHasher_BySha2_single_character() {
	// Hash single character using SHA2-256
	hasher := hash.NewHasher().FromString("a").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
}

func ExampleHasher_BySha2_unicode() {
	// Hash Unicode string using SHA2-256
	hasher := hash.NewHasher().FromString("你好世界").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: beca6335b20ff57ccc47403ef4d9e0b8fccb4442b3151c2e7d50050673d43172
}

func ExampleHasher_BySha2_digits() {
	// Hash digits using SHA2-256
	hasher := hash.NewHasher().FromString("1234567890").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646
}

func ExampleHasher_BySha2_alphabet() {
	// Hash alphabet using SHA2-256
	hasher := hash.NewHasher().FromString("abcdefghijklmnopqrstuvwxyz").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: 71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73
}

func ExampleHasher_BySha2_alphanumeric() {
	// Hash alphanumeric string using SHA2-256
	hasher := hash.NewHasher().FromString("abc123def456").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: e861b2eab679927cfa36fe256e9deb1969b0468ad0744d61064f9d188333aec6
}

func ExampleHasher_BySha2_quick_brown_fox() {
	// Hash "The quick brown fox jumps over the lazy dog" using SHA2-256
	hasher := hash.NewHasher().FromString("The quick brown fox jumps over the lazy dog").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
}

func ExampleHasher_BySha2_large_data() {
	// Hash large data using SHA2-256
	largeData := make([]byte, 1000)
	for i := range largeData {
		largeData[i] = 'a'
	}
	hasher := hash.NewHasher().FromBytes(largeData).BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("SHA2-256 hash:", hashValue)
	// Output: SHA2-256 hash: 41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3
}

func ExampleHasher_BySha2_base64_output() {
	// Hash string and output as base64
	hasher := hash.NewHasher().FromString("hello").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToBase64String()
	fmt.Println("SHA2-256 hash (base64):", hashValue)
	// Output: SHA2-256 hash (base64): LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=
}

func ExampleHasher_BySha2_raw_bytes() {
	// Hash string and get raw bytes
	hasher := hash.NewHasher().FromString("hello").BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashBytes := hasher.ToRawBytes()
	fmt.Printf("SHA2-256 hash (bytes): %v\n", hashBytes)
	// Output: SHA2-256 hash (bytes): [44 242 77 186 95 176 163 14 38 232 59 42 197 185 226 158 27 22 30 92 31 167 66 94 115 4 51 98 147 139 152 36]
}

func ExampleHasher_BySha2_all_sizes() {
	// Hash string using all SHA2 sizes
	data := "hello"
	sizes := []int{224, 256, 384, 512}

	for _, size := range sizes {
		hasher := hash.NewHasher().FromString(data).BySha2(size)
		if hasher.Error != nil {
			fmt.Printf("SHA2-%d error: %v\n", size, hasher.Error)
			continue
		}
		hashValue := hasher.ToHexString()
		fmt.Printf("SHA2-%d: %s\n", size, hashValue)
	}
	// Output: SHA2-224: ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193
	// SHA2-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	// SHA2-384: 59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f
	// SHA2-512: 9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043
}

func ExampleHasher_BySha2_hmac() {
	// Hash string with HMAC using SHA2-256
	hasher := hash.NewHasher().FromString("hello").WithKey([]byte("secret")).BySha2(256)
	if hasher.Error != nil {
		fmt.Println("Hash error:", hasher.Error)
		return
	}
	hashValue := hasher.ToHexString()
	fmt.Println("HMAC-SHA2-256 hash:", hashValue)
	// Output: HMAC-SHA2-256 hash: 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b
}

func ExampleHasher_BySha2_hmac_all_sizes() {
	// Hash string with HMAC using all SHA2 sizes
	data := "hello"
	key := []byte("secret")
	sizes := []int{224, 256, 384, 512}

	for _, size := range sizes {
		hasher := hash.NewHasher().FromString(data).WithKey(key).BySha2(size)
		if hasher.Error != nil {
			fmt.Printf("HMAC-SHA2-%d error: %v\n", size, hasher.Error)
			continue
		}
		hashValue := hasher.ToHexString()
		fmt.Printf("HMAC-SHA2-%d: %s\n", size, hashValue)
	}
	// Output: HMAC-SHA2-224: a3e965681c72dd4d7fcf2583a1de04f6900b90b30b3a5c93fe5ac497
	// HMAC-SHA2-256: 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b
	// HMAC-SHA2-384: 7e1e620ca0068fd1fce00c1ad3f5c6dbb12874dd2fb9c26502d09d0d804f2c0ba1d921b9458416cba480417571001e18
	// HMAC-SHA2-512: db1595ae88a62fd151ec1cba81b98c39df82daae7b4cb9820f446d5bf02f1dcfca6683d88cab3e273f5963ab8ec469a746b5b19086371239f67d1e5f99a79440
}

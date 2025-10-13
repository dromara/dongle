package sm4

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
)

var (
	sm4Key = []byte("1234567890123456")
	sm4IV  = []byte("1234567890123456")
)

// Benchmark data for various sizes
var benchmarkData = map[string][]byte{
	"empty":            {},
	"small":            []byte("hello"),
	"medium":           []byte("hello world, this is a medium sized test data for SM4 encryption"),
	"large":            make([]byte, 1024),
	"very_large":       make([]byte, 10240),
	"block_aligned":    make([]byte, 1024), // 16-byte aligned for SM4
	"random_small":     make([]byte, 64),
	"random_medium":    make([]byte, 512),
	"random_large":     make([]byte, 4096),
	"repeated_pattern": bytes.Repeat([]byte("1234567890123456"), 64), // 1024 bytes
}

// Test vectors for SM4 algorithm
// These are standard test vectors from the SM4 specification
var testVectors = []struct {
	key        []byte
	plaintext  []byte
	ciphertext []byte
}{
	{
		key:        []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		plaintext:  []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
		ciphertext: []byte{0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46},
	},
}

func TestSM4EncryptDecrypt(t *testing.T) {
	for i, test := range testVectors {
		// Create cipher
		cipher, err := NewCipher(test.key)
		if err != nil {
			t.Errorf("Test %d: Failed to create cipher: %v", i, err)
			continue
		}

		// Encrypt
		encrypted := make([]byte, BlockSize)
		cipher.Encrypt(encrypted, test.plaintext)

		// Check encryption result
		for j := range encrypted {
			if encrypted[j] != test.ciphertext[j] {
				t.Errorf("Test %d: Encryption mismatch at byte %d: expected 0x%02x, got 0x%02x", i, j, test.ciphertext[j], encrypted[j])
			}
		}

		// Decrypt
		decrypted := make([]byte, BlockSize)
		cipher.Decrypt(decrypted, encrypted)

		// Check decryption result
		for j := range decrypted {
			if decrypted[j] != test.plaintext[j] {
				t.Errorf("Test %d: Decryption mismatch at byte %d: expected 0x%02x, got 0x%02x", i, j, test.plaintext[j], decrypted[j])
			}
		}
	}
}

// BenchmarkStdEncrypter_Encrypt benchmarks the standard encrypter for various data types
func BenchmarkStdEncrypter_Encrypt(b *testing.B) {
	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	// Initialize random data for benchmarks
	rand.Read(benchmarkData["large"])
	rand.Read(benchmarkData["very_large"])
	rand.Read(benchmarkData["random_small"])
	rand.Read(benchmarkData["random_medium"])
	rand.Read(benchmarkData["random_large"])

	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			encrypter := NewStdEncrypter(c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encrypter.Encrypt(data)
			}
		})
	}
}

// BenchmarkStdDecrypter_Decrypt benchmarks the standard decrypter for various data types
func BenchmarkStdDecrypter_Decrypt(b *testing.B) {
	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	// First encrypt data to get encrypted bytes for decryption
	encrypter := NewStdEncrypter(c)
	encryptedData := make(map[string][]byte)
	for name, data := range benchmarkData {
		encrypted, err := encrypter.Encrypt(data)
		if err != nil {
			b.Fatalf("Failed to encrypt %s: %v", name, err)
		}
		encryptedData[name] = encrypted
	}

	for name, encrypted := range encryptedData {
		b.Run(name, func(b *testing.B) {
			decrypter := NewStdDecrypter(c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Decrypt(encrypted)
			}
		})
	}
}

// BenchmarkStreamEncrypter_Write benchmarks the streaming encrypter for various data types
func BenchmarkStreamEncrypter_Write(b *testing.B) {
	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				encrypter.Write(data)
				encrypter.Close()
			}
		})
	}
}

// BenchmarkStreamDecrypter_Read benchmarks the streaming decrypter for various data types
func BenchmarkStreamDecrypter_Read(b *testing.B) {
	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	// First encrypt data to get encrypted bytes for decryption
	encryptedData := make(map[string][]byte)
	for name, data := range benchmarkData {
		var buf bytes.Buffer
		streamEncrypter := NewStreamEncrypter(&buf, c)
		streamEncrypter.Write(data)
		streamEncrypter.Close()
		encryptedData[name] = buf.Bytes()
	}

	for name, encrypted := range encryptedData {
		b.Run(name, func(b *testing.B) {
			decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), c)
			buf := make([]byte, 1024)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Read(buf)
			}
		})
	}
}

// BenchmarkEncryptionSizes benchmarks encryption performance for different data sizes
func BenchmarkEncryptionSizes(b *testing.B) {
	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	sizes := []int{64, 128, 256, 512, 1024, 2048, 4096, 8192}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			encrypter := NewStdEncrypter(c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encrypter.Encrypt(data)
			}
		})
	}
}

// BenchmarkDecryptionSizes benchmarks decryption performance for different data sizes
func BenchmarkDecryptionSizes(b *testing.B) {
	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	sizes := []int{64, 128, 256, 512, 1024, 2048, 4096, 8192}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		// Encrypt data first
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(data)
		if err != nil {
			b.Fatalf("Failed to encrypt data of size %d: %v", size, err)
		}

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			decrypter := NewStdDecrypter(c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Decrypt(encrypted)
			}
		})
	}
}

// BenchmarkCipherModes benchmarks performance with different cipher modes
func BenchmarkCipherModes(b *testing.B) {
	data := make([]byte, 1024)
	rand.Read(data)

	modes := []cipher.BlockMode{cipher.CBC, cipher.ECB, cipher.CFB, cipher.OFB, cipher.CTR}
	for _, mode := range modes {
		c := cipher.NewSm4Cipher(mode)
		c.SetKey(sm4Key)

		// Set appropriate parameters for each mode
		switch mode {
		case cipher.CBC, cipher.CFB, cipher.OFB:
			c.SetIV(sm4IV)
		case cipher.CTR:
			c.SetIV([]byte("123456789012")) // 12 bytes nonce for CTR
		}

		// Set padding for modes that need it
		if mode != cipher.CTR && mode != cipher.CFB && mode != cipher.OFB {
			c.SetPadding(cipher.PKCS7)
		}

		b.Run(fmt.Sprintf("encrypt_%s", mode), func(b *testing.B) {
			encrypter := NewStdEncrypter(c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encrypter.Encrypt(data)
			}
		})

		b.Run(fmt.Sprintf("decrypt_%s", mode), func(b *testing.B) {
			encrypter := NewStdEncrypter(c)
			encrypted, err := encrypter.Encrypt(data)
			if err != nil {
				b.Fatalf("Failed to encrypt: %v", err)
			}

			decrypter := NewStdDecrypter(c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Decrypt(encrypted)
			}
		})
	}
}

// BenchmarkStreamingVsStandard compares streaming vs standard operations
func BenchmarkStreamingVsStandard(b *testing.B) {
	data := make([]byte, 10240) // 10KB for better streaming comparison
	rand.Read(data)

	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	b.Run("standard_encrypt", func(b *testing.B) {
		encrypter := NewStdEncrypter(c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypter.Encrypt(data)
		}
	})

	b.Run("streaming_encrypt", func(b *testing.B) {
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			encrypter.Write(data)
			encrypter.Close()
		}
	})

	// For decryption, we need encrypted data first
	encrypter := NewStdEncrypter(c)
	encrypted, err := encrypter.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to encrypt: %v", err)
	}

	b.Run("standard_decrypt", func(b *testing.B) {
		decrypter := NewStdDecrypter(c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Decrypt(encrypted)
		}
	})

	b.Run("streaming_decrypt", func(b *testing.B) {
		decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), c)
		buf := make([]byte, 1024)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Read(buf)
		}
	})
}

// BenchmarkMemoryAllocation measures memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	data := make([]byte, 1024)
	rand.Read(data)

	b.Run("std_encrypt_alloc", func(b *testing.B) {
		encrypter := NewStdEncrypter(c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypter.Encrypt(data)
		}
	})

	b.Run("stream_encrypt_alloc", func(b *testing.B) {
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			encrypter.Write(data)
			encrypter.Close()
		}
	})

	// Encrypt data for decryption benchmarks
	encrypter := NewStdEncrypter(c)
	encrypted, err := encrypter.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to encrypt: %v", err)
	}

	b.Run("std_decrypt_alloc", func(b *testing.B) {
		decrypter := NewStdDecrypter(c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Decrypt(encrypted)
		}
	})

	b.Run("stream_decrypt_alloc", func(b *testing.B) {
		decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), c)
		buf := make([]byte, 1024)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Read(buf)
		}
	})
}

// BenchmarkLargeFileStreaming benchmarks streaming performance for large files
func BenchmarkLargeFileStreaming(b *testing.B) {
	// Test with different file sizes to show streaming benefits
	fileSizes := []int{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB

	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	for _, size := range fileSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("encrypt_%d_bytes", size), func(b *testing.B) {
			b.Run("standard", func(b *testing.B) {
				encrypter := NewStdEncrypter(c)
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					encrypter.Encrypt(data)
				}
			})

			b.Run("streaming", func(b *testing.B) {
				var buf bytes.Buffer
				encrypter := NewStreamEncrypter(&buf, c)
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					buf.Reset()
					encrypter.Write(data)
					encrypter.Close()
				}
			})
		})

		// For decryption, we need encrypted data first
		encrypter := NewStdEncrypter(c)
		encrypted, err := encrypter.Encrypt(data)
		if err != nil {
			b.Fatalf("Failed to encrypt %d bytes: %v", size, err)
		}

		b.Run(fmt.Sprintf("decrypt_%d_bytes", size), func(b *testing.B) {
			b.Run("standard", func(b *testing.B) {
				decrypter := NewStdDecrypter(c)
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					decrypter.Decrypt(encrypted)
				}
			})

			b.Run("streaming", func(b *testing.B) {
				decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), c)
				buf := make([]byte, 1024)
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					decrypter.Read(buf)
				}
			})
		})
	}
}

// BenchmarkStreamingBufferSizes benchmarks streaming with different buffer sizes
func BenchmarkStreamingBufferSizes(b *testing.B) {
	data := make([]byte, 10240) // 10KB test data
	rand.Read(data)

	c := cipher.NewSm4Cipher(cipher.CBC)
	c.SetKey(sm4Key)
	c.SetIV(sm4IV)
	c.SetPadding(cipher.PKCS7)

	// Encrypt data first
	encrypter := NewStdEncrypter(c)
	encrypted, err := encrypter.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to encrypt: %v", err)
	}

	bufferSizes := []int{64, 128, 256, 512, 1024, 2048}
	for _, bufSize := range bufferSizes {
		b.Run(fmt.Sprintf("buffer_%d", bufSize), func(b *testing.B) {
			decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), c)
			buf := make([]byte, bufSize)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Read(buf)
			}
		})
	}
}

package des

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/mock"
)

// Benchmark data for various sizes
var benchmarkData = map[string][]byte{
	"empty":            {},
	"small":            []byte("hello"),
	"medium":           []byte("hello world, this is a medium sized test data for DES encryption"),
	"large":            make([]byte, 1024),
	"very_large":       make([]byte, 10240),
	"block_aligned":    make([]byte, 1024), // 8-byte aligned for DES
	"random_small":     make([]byte, 64),
	"random_medium":    make([]byte, 512),
	"random_large":     make([]byte, 4096),
	"repeated_pattern": bytes.Repeat([]byte("12345678"), 128), // 1024 bytes
}

// Test keys and IVs are defined in des_unit_test.go

func init() {
	// Initialize random data
	rand.Read(benchmarkData["large"])
	rand.Read(benchmarkData["very_large"])
	rand.Read(benchmarkData["random_small"])
	rand.Read(benchmarkData["random_medium"])
	rand.Read(benchmarkData["random_large"])
}

// BenchmarkStdEncrypter_Encrypt benchmarks the standard encrypter for various data types
func BenchmarkStdEncrypter_Encrypt(b *testing.B) {
	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
	c.SetPadding(cipher.PKCS7)

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
	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
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
	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
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
	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
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
	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
	c.SetPadding(cipher.PKCS7)

	sizes := []int{64, 128, 256, 512, 1024, 2048, 4096, 8192}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(testing.BenchmarkResult{}.String(), func(b *testing.B) {
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
	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
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

		b.Run(testing.BenchmarkResult{}.String(), func(b *testing.B) {
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

	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
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
	c := cipher.NewDesCipher(cipher.CBC)
	c.SetKey(key8)
	c.SetIV(iv8)
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

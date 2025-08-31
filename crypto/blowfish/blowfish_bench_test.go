package blowfish

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
	"medium":           []byte("hello world, this is a medium sized test data for Blowfish encryption"),
	"large":            make([]byte, 1024),
	"very_large":       make([]byte, 10240),
	"block_aligned":    make([]byte, 1024), // 8-byte aligned for Blowfish
	"random_small":     make([]byte, 64),
	"random_medium":    make([]byte, 512),
	"random_large":     make([]byte, 4096),
	"repeated_pattern": bytes.Repeat([]byte("12345678"), 128), // 1024 bytes
}

// Test keys and IVs are defined in blowfish_unit_test.go
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
	c := cipher.NewBlowfishCipher(cipher.CBC)
	c.SetKey([]byte("1234567890123456")) // 16 bytes key
	c.SetIV([]byte("12345678"))          // 8 bytes IV
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

// BenchmarkStreamingVsStandard compares streaming vs standard operations
func BenchmarkStreamingVsStandard(b *testing.B) {
	data := make([]byte, 10240) // 10KB for better streaming comparison
	rand.Read(data)

	c := cipher.NewBlowfishCipher(cipher.CBC)
	c.SetKey([]byte("1234567890123456")) // 16 bytes key
	c.SetIV([]byte("12345678"))          // 8 bytes IV
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

package rc4

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/dromara/dongle/mock"
)

// Benchmark data for various sizes
var benchmarkData = map[string][]byte{
	"small":      make([]byte, 64),
	"medium":     make([]byte, 1024),
	"large":      make([]byte, 8192),
	"very_large": make([]byte, 65536), // 64KB
}

var testKey = []byte("test-rc4-key-for-benchmark")

func initBenchData() {
	// Initialize random data
	for _, data := range benchmarkData {
		rand.Read(data)
	}
}

// BenchmarkStdEncrypter_Encrypt benchmarks the standard encrypter for various data sizes
func BenchmarkStdEncrypter_Encrypt(b *testing.B) {
	initBenchData()
	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			enc := NewStdEncrypter(testKey)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				enc.Encrypt(data)
			}
		})
	}
}

// BenchmarkStdDecrypter_Decrypt benchmarks the standard decrypter for various data sizes
func BenchmarkStdDecrypter_Decrypt(b *testing.B) {
	initBenchData()
	// Pre-encrypt all test data
	encryptedData := make(map[string][]byte)
	enc := NewStdEncrypter(testKey)
	for name, data := range benchmarkData {
		encrypted, _ := enc.Encrypt(data)
		encryptedData[name] = encrypted
	}

	for name, encrypted := range encryptedData {
		b.Run(name, func(b *testing.B) {
			dec := NewStdDecrypter(testKey)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				dec.Decrypt(encrypted)
			}
		})
	}
}

// BenchmarkStreamingVsStandard compares streaming vs standard operations for large data
func BenchmarkStreamingVsStandard(b *testing.B) {
	initBenchData()
	data := make([]byte, 32768) // 32KB for better streaming comparison
	rand.Read(data)

	b.Run("standard_encrypt", func(b *testing.B) {
		enc := NewStdEncrypter(testKey)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			enc.Encrypt(data)
		}
	})

	b.Run("streaming_encrypt", func(b *testing.B) {
		var buf bytes.Buffer
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			enc := NewStreamEncrypter(&buf, testKey)
			enc.Write(data)
			enc.Close()
		}
	})

	// For decryption, we need encrypted data first
	enc := NewStdEncrypter(testKey)
	encrypted, _ := enc.Encrypt(data)

	b.Run("standard_decrypt", func(b *testing.B) {
		dec := NewStdDecrypter(testKey)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			dec.Decrypt(encrypted)
		}
	})

	b.Run("streaming_decrypt", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := mock.NewFile(encrypted, "test.bin")
			dec := NewStreamDecrypter(reader, testKey)

			// Read all data
			buf := make([]byte, len(data))
			_, err := dec.Read(buf)
			if err != nil && err != io.EOF {
				b.Fatalf("Decrypt failed: %v", err)
			}
		}
	})
}

// BenchmarkCipherReuse compares cipher creation vs reuse performance
func BenchmarkCipherReuse(b *testing.B) {
	initBenchData()
	data := make([]byte, 1024)
	rand.Read(data)

	b.Run("new_cipher_each_time", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Simulate the old behavior: create cipher each time
			enc := &StdEncrypter{key: testKey}
			enc.Encrypt(data)
		}
	})

	b.Run("reuse_cipher", func(b *testing.B) {
		enc := NewStdEncrypter(testKey)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			enc.Encrypt(data)
		}
	})
}

// BenchmarkMemoryEfficiency tests memory allocation efficiency
func BenchmarkMemoryEfficiency(b *testing.B) {
	initBenchData()
	data := make([]byte, 4096)
	rand.Read(data)

	// Pre-encrypt data for decryption tests
	enc := NewStdEncrypter(testKey)
	encrypted, _ := enc.Encrypt(data)

	b.Run("stream_decrypt_old_style", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := mock.NewFile(encrypted, "test.bin")
			dec := NewStreamDecrypter(reader, testKey)

			// Simulate old behavior with temporary buffer allocation
			buf := make([]byte, 1024) // Small buffer to force multiple reads
			var result []byte
			for {
				n, err := dec.Read(buf)
				if n > 0 {
					// Old behavior would create temporary buffer here
					temp := make([]byte, n)
					copy(temp, buf[:n])
					result = append(result, temp...)
				}
				if err != nil {
					break
				}
			}
		}
	})

	b.Run("stream_decrypt_new_style", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := mock.NewFile(encrypted, "test.bin")
			dec := NewStreamDecrypter(reader, testKey)

			// New behavior: decrypt in-place
			buf := make([]byte, len(data))
			_, err := dec.Read(buf)
			if err != nil && err != io.EOF {
				b.Fatalf("Decrypt failed: %v", err)
			}
		}
	})
}

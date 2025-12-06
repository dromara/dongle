package chacha20poly1305

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
	"github.com/dromara/dongle/internal/mock"
)

// Benchmark data for various sizes
var benchmarkData = map[string][]byte{
	"small":      make([]byte, 64),
	"medium":     make([]byte, 1024),
	"large":      make([]byte, 8192),
	"very_large": make([]byte, 65536), // 64KB
}

var testKey = []byte("dongle1234567890abcdef123456789x") // 32 bytes for ChaCha20-Poly1305
var testNonce = []byte("123456789012")                   // 12 bytes for ChaCha20-Poly1305
var testAAD = []byte("benchmark aad data")

func initBenchData() {
	// Initialize random data for benchmarking
	for name, data := range benchmarkData {
		rand.Read(data)
		benchmarkData[name] = data
	}
}

// BenchmarkStdEncrypter_Encrypt benchmarks the standard encrypter for various data sizes
func BenchmarkStdEncrypter_Encrypt(b *testing.B) {
	initBenchData()
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(testKey)
	c.SetNonce(testNonce)
	c.SetAAD(testAAD)

	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			enc := NewStdEncrypter(c)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := enc.Encrypt(data)
				if err != nil {
					b.Fatalf("Encrypt failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkStdDecrypter_Decrypt benchmarks the standard decrypter for various data sizes
func BenchmarkStdDecrypter_Decrypt(b *testing.B) {
	initBenchData()
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(testKey)
	c.SetNonce(testNonce)
	c.SetAAD(testAAD)

	// Pre-encrypt all test data
	encryptedData := make(map[string][]byte)
	enc := NewStdEncrypter(c)
	for name, data := range benchmarkData {
		encrypted, err := enc.Encrypt(data)
		if err != nil {
			b.Fatalf("Failed to prepare encrypted data: %v", err)
		}
		encryptedData[name] = encrypted
	}

	for name, encrypted := range encryptedData {
		b.Run(name, func(b *testing.B) {
			// Create fresh cipher for each benchmark
			c2 := cipher.NewChaCha20Poly1305Cipher()
			c2.SetKey(testKey)
			c2.SetNonce(testNonce)
			c2.SetAAD(testAAD)
			dec := NewStdDecrypter(c2)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := dec.Decrypt(encrypted)
				if err != nil {
					b.Fatalf("Decrypt failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkStreamingVsStandard compares streaming vs standard operations for large data
func BenchmarkStreamingVsStandard(b *testing.B) {
	initBenchData()
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(testKey)
	c.SetNonce(testNonce)
	c.SetAAD(testAAD)

	data := make([]byte, 32768) // 32KB for better streaming comparison
	rand.Read(data)

	b.Run("standard_encrypt", func(b *testing.B) {
		enc := NewStdEncrypter(c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := enc.Encrypt(data)
			if err != nil {
				b.Fatalf("Encrypt failed: %v", err)
			}
		}
	})

	b.Run("streaming_encrypt", func(b *testing.B) {
		var buf bytes.Buffer
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			c2 := cipher.NewChaCha20Poly1305Cipher()
			c2.SetKey(testKey)
			c2.SetNonce(testNonce)
			c2.SetAAD(testAAD)
			enc := NewStreamEncrypter(&buf, c2)
			_, err := enc.Write(data)
			if err != nil {
				b.Fatalf("Write failed: %v", err)
			}
			err = enc.Close()
			if err != nil {
				b.Fatalf("Close failed: %v", err)
			}
		}
	})

	// For decryption, we need encrypted data first
	enc := NewStdEncrypter(c)
	encrypted, err := enc.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to prepare encrypted data: %v", err)
	}

	b.Run("standard_decrypt", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			c2 := cipher.NewChaCha20Poly1305Cipher()
			c2.SetKey(testKey)
			c2.SetNonce(testNonce)
			c2.SetAAD(testAAD)
			dec := NewStdDecrypter(c2)
			_, err := dec.Decrypt(encrypted)
			if err != nil {
				b.Fatalf("Decrypt failed: %v", err)
			}
		}
	})

	b.Run("streaming_decrypt", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := mock.NewFile(encrypted, "test.bin")
			c2 := cipher.NewChaCha20Poly1305Cipher()
			c2.SetKey(testKey)
			c2.SetNonce(testNonce)
			c2.SetAAD(testAAD)
			dec := NewStreamDecrypter(reader, c2)

			// Read all data
			buf := make([]byte, len(data)+16) // Extra space for auth tag
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
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(testKey)
	c.SetNonce(testNonce)
	c.SetAAD(testAAD)

	data := make([]byte, 1024)
	rand.Read(data)

	b.Run("new_cipher_each_time", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Simulate the old behavior: create cipher each time
			enc := &StdEncrypter{cipher: *c}
			_, err := enc.Encrypt(data)
			if err != nil {
				b.Fatalf("Encrypt failed: %v", err)
			}
		}
	})

	b.Run("reuse_cipher", func(b *testing.B) {
		enc := NewStdEncrypter(c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := enc.Encrypt(data)
			if err != nil {
				b.Fatalf("Encrypt failed: %v", err)
			}
		}
	})
}

// BenchmarkMemoryEfficiency tests memory allocation efficiency
func BenchmarkMemoryEfficiency(b *testing.B) {
	initBenchData()
	c := cipher.NewChaCha20Poly1305Cipher()
	c.SetKey(testKey)
	c.SetNonce(testNonce)
	c.SetAAD(testAAD)

	data := make([]byte, 4096)
	rand.Read(data)

	// Pre-encrypt data for decryption tests
	enc := NewStdEncrypter(c)
	encrypted, err := enc.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to prepare encrypted data: %v", err)
	}

	b.Run("stream_encrypt_chunked", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			c2 := cipher.NewChaCha20Poly1305Cipher()
			c2.SetKey(testKey)
			c2.SetNonce(testNonce)
			c2.SetAAD(testAAD)
			enc := NewStreamEncrypter(&buf, c2)

			// Write data in chunks
			chunkSize := 256
			for offset := 0; offset < len(data); offset += chunkSize {
				end := offset + chunkSize
				if end > len(data) {
					end = len(data)
				}
				_, err := enc.Write(data[offset:end])
				if err != nil {
					b.Fatalf("Write failed: %v", err)
				}
			}
			err := enc.Close()
			if err != nil {
				b.Fatalf("Close failed: %v", err)
			}
		}
	})

	b.Run("stream_decrypt_chunked_read", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := mock.NewFile(encrypted, "test.bin")
			c2 := cipher.NewChaCha20Poly1305Cipher()
			c2.SetKey(testKey)
			c2.SetNonce(testNonce)
			c2.SetAAD(testAAD)
			dec := NewStreamDecrypter(reader, c2)

			// Read in small chunks to test the streaming mechanism
			var result []byte
			buf := make([]byte, 128) // Small buffer
			for {
				n, err := dec.Read(buf)
				if n > 0 {
					result = append(result, buf[:n]...)
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					b.Fatalf("Read failed: %v", err)
				}
			}
		}
	})
}

package tea

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/cipher"
)

// Benchmark data for various sizes
var benchmarkData = map[string][]byte{
	"small":      make([]byte, 64),
	"medium":     make([]byte, 1024),
	"large":      make([]byte, 8192),
	"very_large": make([]byte, 65536), // 64KB
}

var testKey = []byte("dongle-tea-key16") // 16 bytes for TEA

func init() {
	// Initialize random data, ensuring block alignment for TEA (8-byte blocks)
	for name, data := range benchmarkData {
		rand.Read(data)
		// Ensure data is 8-byte aligned for TEA
		if len(data)%8 != 0 {
			benchmarkData[name] = data[:len(data)-len(data)%8]
		}
	}
}

// BenchmarkStdEncrypter_Encrypt benchmarks the standard encrypter for various data sizes
func BenchmarkStdEncrypter_Encrypt(b *testing.B) {
	c := cipher.NewTeaCipher()
	c.SetKey(testKey)

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
	c := cipher.NewTeaCipher()
	c.SetKey(testKey)

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
			dec := NewStdDecrypter(c)
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
	c := cipher.NewTeaCipher()
	c.SetKey(testKey)

	data := make([]byte, 32768) // 32KB for better streaming comparison
	rand.Read(data)
	// Ensure 8-byte alignment for TEA
	data = data[:len(data)-len(data)%8]

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
			enc := NewStreamEncrypter(&buf, c)
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
		dec := NewStdDecrypter(c)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
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
			reader := bytes.NewReader(encrypted)
			dec := NewStreamDecrypter(reader, c)

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
	c := cipher.NewTeaCipher()
	c.SetKey(testKey)

	data := make([]byte, 1024)
	rand.Read(data)
	// Ensure 8-byte alignment
	data = data[:len(data)-len(data)%8]

	b.Run("new_cipher_each_time", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			// Simulate the old behavior: create cipher each time
			enc := &StdEncrypter{cipher: c}
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

// BenchmarkStreamDecryptOptimization tests streaming decryption improvements
func BenchmarkStreamDecryptOptimization(b *testing.B) {
	c := cipher.NewTeaCipher()
	c.SetKey(testKey)

	data := make([]byte, 4096)
	rand.Read(data)
	// Ensure 8-byte alignment
	data = data[:len(data)-len(data)%8]

	// Pre-encrypt data for decryption tests
	enc := NewStdEncrypter(c)
	encrypted, err := enc.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to prepare encrypted data: %v", err)
	}

	b.Run("old_style_block_by_block", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(encrypted)

			// Simulate old block-by-block reading approach
			var result []byte
			buf := make([]byte, 8) // TEA block size
			for {
				n, err := reader.Read(buf)
				if n == 0 {
					break
				}
				if err != nil && err != io.EOF {
					b.Fatalf("Read failed: %v", err)
				}

				// Would decrypt single block here (simulated)
				result = append(result, buf[:n]...)

				if err == io.EOF {
					break
				}
			}
		}
	})

	b.Run("new_style_decrypt_once", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(encrypted)
			dec := NewStreamDecrypter(reader, c)

			// New behavior: decrypt all at once, serve in chunks
			buf := make([]byte, len(data))
			_, err := dec.Read(buf)
			if err != nil && err != io.EOF {
				b.Fatalf("Decrypt failed: %v", err)
			}
		}
	})
}

// BenchmarkMemoryEfficiency tests memory allocation efficiency
func BenchmarkMemoryEfficiency(b *testing.B) {
	c := cipher.NewTeaCipher()
	c.SetKey(testKey)

	data := make([]byte, 4096)
	rand.Read(data)
	// Ensure 8-byte alignment
	data = data[:len(data)-len(data)%8]

	// Pre-encrypt data for decryption tests
	enc := NewStdEncrypter(c)
	encrypted, err := enc.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to prepare encrypted data: %v", err)
	}

	b.Run("stream_encrypt_with_buffering", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			enc := NewStreamEncrypter(&buf, c)

			// Write data in chunks to test buffering
			chunkSize := 24 // Not 8-byte aligned to test buffering
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
			reader := bytes.NewReader(encrypted)
			dec := NewStreamDecrypter(reader, c)

			// Read in small chunks to test the serving mechanism
			var result []byte
			buf := make([]byte, 64) // Small buffer
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

package ed25519

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/mock"
)

// Benchmark data sizes for testing
var benchmarkSizes = []int{64, 256, 1024, 4096, 16384}

// generateBenchmarkData creates test data of specified size
func generateBenchmarkData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// BenchmarkStdSigner benchmarks the standard ED25519 signer
func BenchmarkStdSigner(b *testing.B) {
	// Generate a key pair for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()
	signer := NewStdSigner(kp)

	for _, size := range benchmarkSizes {
		data := generateBenchmarkData(size)
		b.Run(fmt.Sprintf("Sign_%dB", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := signer.Sign(data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStdVerifier benchmarks the standard ED25519 verifier
func BenchmarkStdVerifier(b *testing.B) {
	// Generate a key pair and signature for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()
	signer := NewStdSigner(kp)
	verifier := NewStdVerifier(kp)

	for _, size := range benchmarkSizes {
		data := generateBenchmarkData(size)
		signature, err := signer.Sign(data)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("Verify_%dB", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := verifier.Verify(data, signature)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStreamSigner benchmarks the streaming ED25519 signer
func BenchmarkStreamSigner(b *testing.B) {
	// Generate a key pair for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()

	for _, size := range benchmarkSizes {
		data := generateBenchmarkData(size)
		b.Run(fmt.Sprintf("StreamSign_%dB", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				signer := NewStreamSigner(&buf, kp)
				_, err := signer.Write(data)
				if err != nil {
					b.Fatal(err)
				}
				err = signer.Close()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStreamVerifier benchmarks the streaming ED25519 verifier
func BenchmarkStreamVerifier(b *testing.B) {
	// Generate a key pair and signature for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()
	signer := NewStdSigner(kp)

	for _, size := range benchmarkSizes {
		data := generateBenchmarkData(size)
		signature, err := signer.Sign(data)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("StreamVerify_%dB", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Create a reader with signature data
				sigReader := mock.NewFile(signature, "test.bin")
				verifier := NewStreamVerifier(sigReader, kp)
				_, err := verifier.Write(data)
				if err != nil {
					b.Fatal(err)
				}
				err = verifier.Close()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkKeyPairGeneration benchmarks ED25519 key pair generation
func BenchmarkKeyPairGeneration(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kp := keypair.NewEd25519KeyPair()
		kp.GenKeyPair()
	}
}

// BenchmarkConcurrentSigning benchmarks concurrent signing operations
func BenchmarkConcurrentSigning(b *testing.B) {
	// Generate a key pair for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()
	signer := NewStdSigner(kp)
	data := generateBenchmarkData(1024)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := signer.Sign(data)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkConcurrentVerification benchmarks concurrent verification operations
func BenchmarkConcurrentVerification(b *testing.B) {
	// Generate a key pair and signature for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()
	signer := NewStdSigner(kp)
	verifier := NewStdVerifier(kp)
	data := generateBenchmarkData(1024)
	signature, err := signer.Sign(data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := verifier.Verify(data, signature)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMemoryUsage benchmarks memory allocation patterns
func BenchmarkMemoryUsage(b *testing.B) {
	// Generate a key pair for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()
	signer := NewStdSigner(kp)

	// Test with large data to see memory allocation patterns
	largeData := generateBenchmarkData(1024 * 1024) // 1MB

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := signer.Sign(largeData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStreamingMemoryUsage benchmarks streaming memory allocation patterns
func BenchmarkStreamingMemoryUsage(b *testing.B) {
	// Generate a key pair for benchmarking
	kp := keypair.NewEd25519KeyPair()
	kp.GenKeyPair()

	// Test with large data to see memory allocation patterns
	largeData := generateBenchmarkData(1024 * 1024) // 1MB

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, kp)
		_, err := signer.Write(largeData)
		if err != nil {
			b.Fatal(err)
		}
		err = signer.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

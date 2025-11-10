package sm2

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/mock"
)

// BenchmarkStdEncrypter tests the performance of standard SM2 encryption
func BenchmarkStdEncrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	// Test data
	testData := []byte("Hello, this is a test message for benchmarking SM2 encryption performance!")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		enc := NewStdEncrypter(kp)
		_, err := enc.Encrypt(testData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStdDecrypter tests the performance of standard SM2 decryption
func BenchmarkStdDecrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	// Encrypt test data first
	enc := NewStdEncrypter(kp)
	encrypted, err := enc.Encrypt([]byte("Hello, this is a test message for benchmarking SM2 decryption performance!"))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		dec := NewStdDecrypter(kp)
		_, err := dec.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStreamEncrypter tests the performance of streaming SM2 encryption
func BenchmarkStreamEncrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	// Test data
	testData := []byte("Hello, this is a test message for benchmarking SM2 streaming encryption performance!")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		enc := NewStreamEncrypter(&buf, kp)
		_, err := enc.Write(testData)
		if err != nil {
			b.Fatal(err)
		}
		err = enc.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStreamDecrypter tests the performance of streaming SM2 decryption
func BenchmarkStreamDecrypter(b *testing.B) {
	// Create key pair
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	// Create encrypted data first
	var buf bytes.Buffer
	enc := NewStreamEncrypter(&buf, kp)
	testData := []byte("Hello, this is a test message for benchmarking SM2 streaming decryption performance!")
	_, err = enc.Write(testData)
	if err != nil {
		b.Fatal(err)
	}
	err = enc.Close()
	if err != nil {
		b.Fatal(err)
	}

	encryptedData := buf.Bytes()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := mock.NewFile(encryptedData, "test.bin")
		dec := NewStreamDecrypter(reader, kp)
		result := make([]byte, 100)
		_, err := dec.Read(result)
		if err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}

// BenchmarkLargeData tests performance with larger data sets
func BenchmarkLargeData(b *testing.B) {
	// Create key pair
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	// Create larger test data (1KB)
	testData := make([]byte, 1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Standard_Encryption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			enc := NewStdEncrypter(kp)
			_, err := enc.Encrypt(testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Streaming_Encryption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			enc := NewStreamEncrypter(&buf, kp)
			_, err := enc.Write(testData)
			if err != nil {
				b.Fatal(err)
			}
			err = enc.Close()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkEncryptionOrders tests performance with different cipher orders
func BenchmarkEncryptionOrders(b *testing.B) {
	// Create key pair
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	testData := []byte("Test message for benchmarking different SM2 cipher orders")

	b.Run("C1C3C2_Order", func(b *testing.B) {
		kp.SetOrder(keypair.C1C3C2)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			enc := NewStdEncrypter(kp)
			_, err := enc.Encrypt(testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("C1C2C3_Order", func(b *testing.B) {
		kp.SetOrder(keypair.C1C2C3)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			enc := NewStdEncrypter(kp)
			_, err := enc.Encrypt(testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkWindowSizes tests performance with different window sizes
func BenchmarkWindowSizes(b *testing.B) {
	testData := []byte("Test message for benchmarking different SM2 window sizes")

	for _, windowSize := range []int{2, 3, 4, 5, 6} {
		b.Run(benchmarkName("Window", windowSize), func(b *testing.B) {
			// Create key pair
			kp := keypair.NewSm2KeyPair()
			kp.SetWindow(windowSize)
			err := kp.GenKeyPair()
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				enc := NewStdEncrypter(kp)
				_, err := enc.Encrypt(testData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkKeyGeneration tests SM2 key pair generation performance
func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		kp := keypair.NewSm2KeyPair()
		err := kp.GenKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptDecryptCycle tests full encryption and decryption cycle
func BenchmarkEncryptDecryptCycle(b *testing.B) {
	// Create key pair
	kp := keypair.NewSm2KeyPair()
	err := kp.GenKeyPair()
	if err != nil {
		b.Fatal(err)
	}

	testData := []byte("Test message for benchmarking SM2 encrypt-decrypt cycle")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Encrypt
		enc := NewStdEncrypter(kp)
		ciphertext, err := enc.Encrypt(testData)
		if err != nil {
			b.Fatal(err)
		}

		// Decrypt
		dec := NewStdDecrypter(kp)
		_, err = dec.Decrypt(ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchmarkName generates a benchmark name with size suffix
func benchmarkName(prefix string, size int) string {
	return fmt.Sprintf("%s_%d", prefix, size)
}

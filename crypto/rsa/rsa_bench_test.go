package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/dromara/dongle/crypto/keypair"
	"github.com/dromara/dongle/internal/mock"
)

var (
	benchKeyPair1024 *keypair.RsaKeyPair
	benchKeyPair2048 *keypair.RsaKeyPair
	benchKeyPair4096 *keypair.RsaKeyPair
)

// Benchmark data for various sizes
var benchmarkData = map[string][]byte{
	"empty":            {},
	"small":            []byte("hello"),
	"medium":           []byte("hello world, this is a medium sized test data for RSA encryption"),
	"block_32":         make([]byte, 32),
	"block_64":         make([]byte, 64),
	"block_100":        make([]byte, 100),
	"random_small":     make([]byte, 16),
	"random_medium":    make([]byte, 64),
	"repeated_pattern": bytes.Repeat([]byte("1234567890123456"), 4), // 64 bytes
}

func init() {
	// Initialize key pairs for benchmarking
	benchKeyPair1024 = keypair.NewRsaKeyPair()
	benchKeyPair1024.SetFormat(keypair.PKCS1)
	benchKeyPair1024.SetHash(crypto.SHA256)
	benchKeyPair1024.GenKeyPair(1024)

	benchKeyPair2048 = keypair.NewRsaKeyPair()
	benchKeyPair2048.SetFormat(keypair.PKCS1)
	benchKeyPair2048.SetHash(crypto.SHA256)
	benchKeyPair2048.GenKeyPair(2048)

	benchKeyPair4096 = keypair.NewRsaKeyPair()
	benchKeyPair4096.SetFormat(keypair.PKCS1)
	benchKeyPair4096.SetHash(crypto.SHA256)
	benchKeyPair4096.GenKeyPair(4096)

	// Initialize random data for benchmarks
	rand.Read(benchmarkData["block_32"])
	rand.Read(benchmarkData["block_64"])
	rand.Read(benchmarkData["block_100"])
	rand.Read(benchmarkData["random_small"])
	rand.Read(benchmarkData["random_medium"])
}

// BenchmarkStdEncrypter_Encrypt benchmarks the standard encrypter for various data types
func BenchmarkStdEncrypter_Encrypt(b *testing.B) {
	kp := benchKeyPair2048

	for name, data := range benchmarkData {
		// Skip data that's too large for RSA encryption
		if len(data) > 190 { // RSA 2048 with PKCS1v15 can encrypt up to 245 bytes
			continue
		}
		b.Run(name, func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
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
	kp := benchKeyPair2048

	// First encrypt data to get encrypted bytes for decryption
	encrypter := NewStdEncrypter(kp)
	encryptedData := make(map[string][]byte)
	for name, data := range benchmarkData {
		// Skip data that's too large for RSA encryption
		if len(data) > 190 {
			continue
		}
		encrypted, err := encrypter.Encrypt(data)
		if err != nil {
			b.Fatalf("Failed to encrypt %s: %v", name, err)
		}
		encryptedData[name] = encrypted
	}

	for name, encrypted := range encryptedData {
		b.Run(name, func(b *testing.B) {
			decrypter := NewStdDecrypter(kp)
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
	kp := benchKeyPair2048

	for name, data := range benchmarkData {
		// Skip data that's too large for RSA encryption
		if len(data) > 190 {
			continue
		}
		b.Run(name, func(b *testing.B) {
			var buf bytes.Buffer
			encrypter := NewStreamEncrypter(&buf, kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				encrypter.Write(data)
			}
		})
	}
}

// BenchmarkStreamDecrypter_Read benchmarks the streaming decrypter for various data types
func BenchmarkStreamDecrypter_Read(b *testing.B) {
	kp := benchKeyPair2048

	// First encrypt data to get encrypted bytes for decryption
	encryptedData := make(map[string][]byte)
	for name, data := range benchmarkData {
		// Skip data that's too large for RSA encryption
		if len(data) > 190 {
			continue
		}
		var buf bytes.Buffer
		streamEncrypter := NewStreamEncrypter(&buf, kp)
		streamEncrypter.Write(data)
		encryptedData[name] = buf.Bytes()
	}

	for name, encrypted := range encryptedData {
		b.Run(name, func(b *testing.B) {
			decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), kp)
			buf := make([]byte, 256)
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
	kp := benchKeyPair2048

	// For RSA 2048, max data size is about 190 bytes with PKCS1v15
	sizes := []int{16, 32, 64, 100, 128, 150, 180}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
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
	kp := benchKeyPair2048

	// For RSA 2048, max data size is about 190 bytes with PKCS1v15
	sizes := []int{16, 32, 64, 100, 128, 150, 180}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		// Encrypt data first
		encrypter := NewStdEncrypter(kp)
		encrypted, err := encrypter.Encrypt(data)
		if err != nil {
			b.Fatalf("Failed to encrypt data of size %d: %v", size, err)
		}

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			decrypter := NewStdDecrypter(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Decrypt(encrypted)
			}
		})
	}
}

// BenchmarkKeySizes benchmarks performance with different key sizes
func BenchmarkKeySizes(b *testing.B) {
	data := make([]byte, 64)
	rand.Read(data)

	keyPairs := map[string]*keypair.RsaKeyPair{
		"1024": benchKeyPair1024,
		"2048": benchKeyPair2048,
		"4096": benchKeyPair4096,
	}

	for keyName, kp := range keyPairs {
		b.Run(fmt.Sprintf("encrypt_%s", keyName), func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encrypter.Encrypt(data)
			}
		})

		b.Run(fmt.Sprintf("decrypt_%s", keyName), func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
			encrypted, err := encrypter.Encrypt(data)
			if err != nil {
				b.Fatalf("Failed to encrypt: %v", err)
			}

			decrypter := NewStdDecrypter(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Decrypt(encrypted)
			}
		})
	}
}

// BenchmarkFormats benchmarks performance with different key formats
func BenchmarkFormats(b *testing.B) {
	data := make([]byte, 64)
	rand.Read(data)

	formats := []keypair.RsaKeyFormat{keypair.PKCS1, keypair.PKCS8}
	for _, format := range formats {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(format)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(2048)

		b.Run(fmt.Sprintf("encrypt_%s", format), func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encrypter.Encrypt(data)
			}
		})

		b.Run(fmt.Sprintf("decrypt_%s", format), func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
			encrypted, err := encrypter.Encrypt(data)
			if err != nil {
				b.Fatalf("Failed to encrypt: %v", err)
			}

			decrypter := NewStdDecrypter(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				decrypter.Decrypt(encrypted)
			}
		})
	}
}

// BenchmarkPaddings benchmarks performance with different padding schemes
func BenchmarkPaddings(b *testing.B) {
	data := make([]byte, 64)
	rand.Read(data)

	paddings := []keypair.RsaPaddingScheme{keypair.PKCS1v15, keypair.OAEP}
	for _, padding := range paddings {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetPadding(padding)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(2048)

		b.Run(fmt.Sprintf("encrypt_%s", padding), func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encrypter.Encrypt(data)
			}
		})

		b.Run(fmt.Sprintf("decrypt_%s", padding), func(b *testing.B) {
			encrypter := NewStdEncrypter(kp)
			encrypted, err := encrypter.Encrypt(data)
			if err != nil {
				b.Fatalf("Failed to encrypt: %v", err)
			}

			decrypter := NewStdDecrypter(kp)
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
	data := make([]byte, 100)
	rand.Read(data)

	kp := benchKeyPair2048

	b.Run("standard_encrypt", func(b *testing.B) {
		encrypter := NewStdEncrypter(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypter.Encrypt(data)
		}
	})

	b.Run("streaming_encrypt", func(b *testing.B) {
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			encrypter.Write(data)
		}
	})

	// For decryption, we need encrypted data first
	encrypter := NewStdEncrypter(kp)
	encrypted, err := encrypter.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to encrypt: %v", err)
	}

	b.Run("standard_decrypt", func(b *testing.B) {
		decrypter := NewStdDecrypter(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Decrypt(encrypted)
		}
	})

	b.Run("streaming_decrypt", func(b *testing.B) {
		decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), kp)
		buf := make([]byte, 256)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Read(buf)
		}
	})
}

// BenchmarkMemoryAllocation measures memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	kp := benchKeyPair2048

	data := make([]byte, 100)
	rand.Read(data)

	b.Run("std_encrypt_alloc", func(b *testing.B) {
		encrypter := NewStdEncrypter(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypter.Encrypt(data)
		}
	})

	b.Run("stream_encrypt_alloc", func(b *testing.B) {
		var buf bytes.Buffer
		encrypter := NewStreamEncrypter(&buf, kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			encrypter.Write(data)
		}
	})

	// Encrypt data for decryption benchmarks
	encrypter := NewStdEncrypter(kp)
	encrypted, err := encrypter.Encrypt(data)
	if err != nil {
		b.Fatalf("Failed to encrypt: %v", err)
	}

	b.Run("std_decrypt_alloc", func(b *testing.B) {
		decrypter := NewStdDecrypter(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Decrypt(encrypted)
		}
	})

	b.Run("stream_decrypt_alloc", func(b *testing.B) {
		decrypter := NewStreamDecrypter(mock.NewFile(encrypted, "test.bin"), kp)
		buf := make([]byte, 256)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decrypter.Read(buf)
		}
	})
}

// BenchmarkStdSigner_Sign benchmarks the standard signer for various data types
func BenchmarkStdSigner_Sign(b *testing.B) {
	kp := benchKeyPair2048

	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			signer := NewStdSigner(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				signer.Sign(data)
			}
		})
	}
}

// BenchmarkStdVerifier_Verify benchmarks the standard verifier for various data types
func BenchmarkStdVerifier_Verify(b *testing.B) {
	kp := benchKeyPair2048

	// First sign data to get signatures for verification
	signer := NewStdSigner(kp)
	signatureData := make(map[string][]byte)
	for name, data := range benchmarkData {
		signature, err := signer.Sign(data)
		if err != nil {
			b.Fatalf("Failed to sign %s: %v", name, err)
		}
		signatureData[name] = signature
	}

	for name, signature := range signatureData {
		data := benchmarkData[name]
		b.Run(name, func(b *testing.B) {
			verifier := NewStdVerifier(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				verifier.Verify(data, signature)
			}
		})
	}
}

// BenchmarkStreamSigner_Sign benchmarks the stream signer for various data types
func BenchmarkStreamSigner_Sign(b *testing.B) {
	kp := benchKeyPair2048

	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			var buf bytes.Buffer
			signer := NewStreamSigner(&buf, kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				signer.Write(data)
				signer.Close()
			}
		})
	}
}

// BenchmarkStreamVerifier_Verify benchmarks the stream verifier for various data types
func BenchmarkStreamVerifier_Verify(b *testing.B) {
	kp := benchKeyPair2048

	// First sign data to get signatures for verification
	signatureData := make(map[string][]byte)
	for name, data := range benchmarkData {
		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, kp)
		signer.Write(data)
		signer.Close()
		signatureData[name] = buf.Bytes()
	}

	for name, signature := range signatureData {
		data := benchmarkData[name]
		b.Run(name, func(b *testing.B) {
			verifier := NewStreamVerifier(mock.NewFile(signature, "sig.bin"), kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				verifier.Write(data)
				verifier.Close()
			}
		})
	}
}

// BenchmarkSigningSizes benchmarks signing performance for different data sizes
func BenchmarkSigningSizes(b *testing.B) {
	kp := benchKeyPair2048

	sizes := []int{16, 64, 256, 1024, 4096, 10240}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			signer := NewStdSigner(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				signer.Sign(data)
			}
		})
	}
}

// BenchmarkVerificationSizes benchmarks verification performance for different data sizes
func BenchmarkVerificationSizes(b *testing.B) {
	kp := benchKeyPair2048

	sizes := []int{16, 64, 256, 1024, 4096, 10240}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		// Sign data first
		signer := NewStdSigner(kp)
		signature, err := signer.Sign(data)
		if err != nil {
			b.Fatalf("Failed to sign data of size %d: %v", size, err)
		}

		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			verifier := NewStdVerifier(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				verifier.Verify(data, signature)
			}
		})
	}
}

// BenchmarkSigningKeySizes benchmarks signing performance with different key sizes
func BenchmarkSigningKeySizes(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)

	keyPairs := map[string]*keypair.RsaKeyPair{
		"1024": benchKeyPair1024,
		"2048": benchKeyPair2048,
		"4096": benchKeyPair4096,
	}

	for keyName, kp := range keyPairs {
		b.Run(fmt.Sprintf("sign_%s", keyName), func(b *testing.B) {
			signer := NewStdSigner(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				signer.Sign(data)
			}
		})

		b.Run(fmt.Sprintf("verify_%s", keyName), func(b *testing.B) {
			signer := NewStdSigner(kp)
			signature, err := signer.Sign(data)
			if err != nil {
				b.Fatalf("Failed to sign: %v", err)
			}

			verifier := NewStdVerifier(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				verifier.Verify(data, signature)
			}
		})
	}
}

// BenchmarkSigningPaddings benchmarks signing performance with different padding schemes
func BenchmarkSigningPaddings(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)

	paddings := []keypair.RsaPaddingScheme{keypair.PKCS1v15, keypair.PSS}
	for _, padding := range paddings {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetPadding(padding)
		kp.SetHash(crypto.SHA256)
		kp.GenKeyPair(2048)

		b.Run(fmt.Sprintf("sign_%s", padding), func(b *testing.B) {
			signer := NewStdSigner(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				signer.Sign(data)
			}
		})

		b.Run(fmt.Sprintf("verify_%s", padding), func(b *testing.B) {
			signer := NewStdSigner(kp)
			signature, err := signer.Sign(data)
			if err != nil {
				b.Fatalf("Failed to sign: %v", err)
			}

			verifier := NewStdVerifier(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				verifier.Verify(data, signature)
			}
		})
	}
}

// BenchmarkHashAlgorithms benchmarks performance with different hash algorithms
func BenchmarkHashAlgorithms(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)

	hashAlgos := []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512}
	for _, hashAlgo := range hashAlgos {
		kp := keypair.NewRsaKeyPair()
		kp.SetFormat(keypair.PKCS1)
		kp.SetHash(hashAlgo)
		kp.GenKeyPair(2048)

		b.Run(fmt.Sprintf("sign_%s", hashAlgo), func(b *testing.B) {
			signer := NewStdSigner(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				signer.Sign(data)
			}
		})

		b.Run(fmt.Sprintf("verify_%s", hashAlgo), func(b *testing.B) {
			signer := NewStdSigner(kp)
			signature, err := signer.Sign(data)
			if err != nil {
				b.Fatalf("Failed to sign: %v", err)
			}

			verifier := NewStdVerifier(kp)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				verifier.Verify(data, signature)
			}
		})
	}
}

// BenchmarkSigningStreamingVsStandard compares streaming vs standard signing operations
func BenchmarkSigningStreamingVsStandard(b *testing.B) {
	data := make([]byte, 1024)
	rand.Read(data)

	kp := benchKeyPair2048

	b.Run("standard_sign", func(b *testing.B) {
		signer := NewStdSigner(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			signer.Sign(data)
		}
	})

	b.Run("streaming_sign", func(b *testing.B) {
		var buf bytes.Buffer
		signer := NewStreamSigner(&buf, kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			signer.Write(data)
			signer.Close()
		}
	})

	// For verification, we need signature data first
	signer := NewStdSigner(kp)
	signature, err := signer.Sign(data)
	if err != nil {
		b.Fatalf("Failed to sign: %v", err)
	}

	b.Run("standard_verify", func(b *testing.B) {
		verifier := NewStdVerifier(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			verifier.Verify(data, signature)
		}
	})

	b.Run("streaming_verify", func(b *testing.B) {
		verifier := NewStreamVerifier(mock.NewFile(signature, "sig.bin"), kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			verifier.Write(data)
			verifier.Close()
		}
	})
}

// BenchmarkKeyGeneration benchmarks key pair generation for different key sizes
func BenchmarkKeyGeneration(b *testing.B) {
	sizes := []int{1024, 2048, 4096}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("generate_%d", size), func(b *testing.B) {
			kp := keypair.NewRsaKeyPair()
			kp.SetFormat(keypair.PKCS1)
			kp.SetHash(crypto.SHA256)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				kp.GenKeyPair(size)
			}
		})
	}
}

// BenchmarkEncryptionComplete benchmarks complete encryption workflow
func BenchmarkEncryptionComplete(b *testing.B) {
	data := make([]byte, 100)
	rand.Read(data)

	kp := benchKeyPair2048

	b.Run("encrypt_decrypt_cycle", func(b *testing.B) {
		encrypter := NewStdEncrypter(kp)
		decrypter := NewStdDecrypter(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encrypted, _ := encrypter.Encrypt(data)
			decrypter.Decrypt(encrypted)
		}
	})
}

// BenchmarkSigningComplete benchmarks complete signing workflow
func BenchmarkSigningComplete(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)

	kp := benchKeyPair2048

	b.Run("sign_verify_cycle", func(b *testing.B) {
		signer := NewStdSigner(kp)
		verifier := NewStdVerifier(kp)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			signature, _ := signer.Sign(data)
			verifier.Verify(data, signature)
		}
	})
}

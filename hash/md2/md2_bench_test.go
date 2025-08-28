package md2

import (
	"testing"
)

// BenchmarkMD2 benchmarks the MD2 hash function with small data
func BenchmarkMD2(b *testing.B) {
	data := []byte("benchmark data for MD2 hash algorithm")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2Large benchmarks the MD2 hash function with large data (1MB)
func BenchmarkMD2Large(b *testing.B) {
	// Create a larger data set for testing
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2Medium benchmarks the MD2 hash function with medium data (1KB)
func BenchmarkMD2Medium(b *testing.B) {
	data := make([]byte, 1024) // 1KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2BlockSize benchmarks the MD2 hash function with exactly one block of data
func BenchmarkMD2BlockSize(b *testing.B) {
	data := make([]byte, BlockSize) // Exactly one block
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2MultipleWrites benchmarks the MD2 hash function with multiple Write calls
func BenchmarkMD2MultipleWrites(b *testing.B) {
	chunks := [][]byte{
		[]byte("first chunk"),
		[]byte("second chunk"),
		[]byte("third chunk"),
		[]byte("fourth chunk"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		for _, chunk := range chunks {
			h.Write(chunk)
		}
		h.Sum(nil)
	}
}

// BenchmarkMD2Reset benchmarks the MD2 hash function with Reset operations
func BenchmarkMD2Reset(b *testing.B) {
	data := []byte("data to hash")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
		h.Reset()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2Empty benchmarks the MD2 hash function with empty data
func BenchmarkMD2Empty(b *testing.B) {
	data := []byte{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2SingleByte benchmarks the MD2 hash function with single byte data
func BenchmarkMD2SingleByte(b *testing.B) {
	data := []byte{0x42}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2Binary benchmarks the MD2 hash function with binary data
func BenchmarkMD2Binary(b *testing.B) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2Chunked benchmarks the MD2 hash function with chunked data writes
func BenchmarkMD2Chunked(b *testing.B) {
	totalSize := 10000
	chunkSize := 100

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()

		for j := 0; j < totalSize; j += chunkSize {
			end := j + chunkSize
			if end > totalSize {
				end = totalSize
			}

			chunk := make([]byte, end-j)
			for k := range chunk {
				chunk[k] = byte(j + k)
			}

			h.Write(chunk)
		}

		h.Sum(nil)
	}
}

// BenchmarkMD2Reuse benchmarks the MD2 hash function with hash reuse
func BenchmarkMD2Reuse(b *testing.B) {
	data := []byte("data to hash multiple times")
	h := New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(nil)
	}
}

// BenchmarkMD2SumWithPrefix benchmarks the MD2 hash function with Sum(prefix)
func BenchmarkMD2SumWithPrefix(b *testing.B) {
	data := []byte("benchmark data")
	prefix := []byte("prefix")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(prefix)
	}
}

// BenchmarkMD2BlockProcessing benchmarks just the block processing function
func BenchmarkMD2BlockProcessing(b *testing.B) {
	data := make([]byte, BlockSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	h := New().(*digest)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.block(data)
	}
}

package sm3

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/mock"
)

// Benchmark data sizes
var dataSizes = []int{
	1024,        // 1KB
	10 * 1024,   // 10KB
	100 * 1024,  // 100KB
	1024 * 1024, // 1MB
}

func BenchmarkSM3Hash(b *testing.B) {
	// Generate test data
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkSM3LargeData(b *testing.B) {
	// Generate large test data
	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := New()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkSM3StreamingVsStandard(b *testing.B) {
	// Generate test data
	data := make([]byte, 10*1024) // 10KB
	rand.Read(data)

	b.Run("standard", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			h := New()
			h.Write(data)
			h.Sum(nil)
		}
	})

	b.Run("streaming", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			h := New()
			// Simulate streaming by writing in chunks
			chunkSize := 64 // Block size
			for j := 0; j < len(data); j += chunkSize {
				end := j + chunkSize
				if end > len(data) {
					end = len(data)
				}
				h.Write(data[j:end])
			}
			h.Sum(nil)
		}
	})
}

func BenchmarkSM3LargeFileStreaming(b *testing.B) {
	for _, size := range dataSizes {
		b.Run(fmt.Sprintf("%dKB", size/1024), func(b *testing.B) {
			// Generate test data
			data := make([]byte, size)
			rand.Read(data)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				h := New()
				// Simulate streaming by writing in chunks
				chunkSize := 64 // Block size
				for j := 0; j < len(data); j += chunkSize {
					end := j + chunkSize
					if end > len(data) {
						end = len(data)
					}
					h.Write(data[j:end])
				}
				h.Sum(nil)
			}
		})
	}
}

func BenchmarkSM3StreamingBufferSizes(b *testing.B) {
	// Generate test data
	data := make([]byte, 20*1024) // 20KB
	rand.Read(data)

	bufferSizes := []int{64, 128, 256, 512, 1024}

	for _, bufferSize := range bufferSizes {
		b.Run(fmt.Sprintf("buffer_%d", bufferSize), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				h := New()
				// Write data in chunks of specified buffer size
				for j := 0; j < len(data); j += bufferSize {
					end := j + bufferSize
					if end > len(data) {
						end = len(data)
					}
					h.Write(data[j:end])
				}
				h.Sum(nil)
			}
		})
	}
}

func BenchmarkSM3WithReader(b *testing.B) {
	// Generate test data
	data := make([]byte, 100*1024) // 100KB
	rand.Read(data)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		h := New()
		reader := mock.NewFile(data, "test.bin")
		io.Copy(h, reader)
		h.Sum(nil)
	}
}

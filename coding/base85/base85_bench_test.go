package base85

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// Benchmark data sizes
var benchmarkSizes = []int{16, 64, 256, 1024, 4096, 16384}

// Benchmark data types
var benchmarkData = map[string][]byte{
	"empty":           {},
	"single_byte":     {0x41},                        // 'A'
	"block_size":      bytes.Repeat([]byte{0x41}, 4), // 4 bytes (complete group)
	"unicode":         []byte("Hello, 世界! 🌍"),
	"leading_zeros":   append([]byte{0x00, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0x41}, 16)...),
	"all_zeros":       bytes.Repeat([]byte{0x00}, 20),
	"mixed_data":      append([]byte{0x00, 0xFF, 0x41, 0x7F}, bytes.Repeat([]byte{0x42}, 16)...),
	"short_string":    []byte("Short"),
	"block_size_plus": bytes.Repeat([]byte{0x41}, 9), // 9 bytes (2 complete groups + 1 byte)
}

// BenchmarkStdEncoder_Encode benchmarks the standard encoder for various data types
func BenchmarkStdEncoder_Encode(b *testing.B) {
	encoder := NewStdEncoder()

	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoder.Encode(data)
			}
		})
	}
}

// BenchmarkStdEncoder_EncodeSizes benchmarks the standard encoder for various data sizes
func BenchmarkStdEncoder_EncodeSizes(b *testing.B) {
	encoder := NewStdEncoder()

	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoder.Encode(data)
			}
		})
	}
}

// BenchmarkStdEncoder_EncodeRandom benchmarks the standard encoder with random data
func BenchmarkStdEncoder_EncodeRandom(b *testing.B) {
	encoder := NewStdEncoder()

	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("random_%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoder.Encode(data)
			}
		})
	}
}

// BenchmarkStdEncoder_EncodeRepeated benchmarks the standard encoder with repeated patterns
func BenchmarkStdEncoder_EncodeRepeated(b *testing.B) {
	encoder := NewStdEncoder()

	patterns := []string{
		"pattern",
		"repeated",
		"data",
	}

	for _, pattern := range patterns {
		for _, size := range benchmarkSizes {
			data := bytes.Repeat([]byte(pattern), size/len(pattern)+1)[:size]

			b.Run(fmt.Sprintf("%s_%d_bytes", pattern, size), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					encoder.Encode(data)
				}
			})
		}
	}
}

// BenchmarkStdDecoder_Decode benchmarks the standard decoder for various data types
func BenchmarkStdDecoder_Decode(b *testing.B) {
	encoder := NewStdEncoder()
	decoder := NewStdDecoder()

	for name, data := range benchmarkData {
		encoded := encoder.Encode(data)

		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(encoded)
			}
		})
	}
}

// BenchmarkStdDecoder_DecodeSizes benchmarks the standard decoder for various data sizes
func BenchmarkStdDecoder_DecodeSizes(b *testing.B) {
	encoder := NewStdEncoder()
	decoder := NewStdDecoder()

	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(encoded)
			}
		})
	}
}

// BenchmarkStdDecoder_DecodeRandom benchmarks the standard decoder with random data
func BenchmarkStdDecoder_DecodeRandom(b *testing.B) {
	decoder := NewStdDecoder()

	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)
		encoded := NewStdEncoder().Encode(data)

		b.Run(fmt.Sprintf("random_%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(encoded)
			}
		})
	}
}

// BenchmarkStdDecoder_DecodeRepeated benchmarks the standard decoder with repeated patterns
func BenchmarkStdDecoder_DecodeRepeated(b *testing.B) {
	encoder := NewStdEncoder()
	decoder := NewStdDecoder()

	patterns := []string{
		"pattern",
		"repeated",
		"data",
	}

	for _, pattern := range patterns {
		for _, size := range benchmarkSizes {
			data := bytes.Repeat([]byte(pattern), size/len(pattern)+1)[:size]
			encoded := encoder.Encode(data)

			b.Run(fmt.Sprintf("%s_%d_bytes", pattern, size), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					decoder.Decode(encoded)
				}
			})
		}
	}
}

// BenchmarkStdDecoder_DecodePadding benchmarks the standard decoder with padding scenarios
func BenchmarkStdDecoder_DecodePadding(b *testing.B) {
	encoder := NewStdEncoder()
	decoder := NewStdDecoder()

	// Test different padding scenarios
	paddingTests := []struct {
		name string
		data []byte
	}{
		{"no_padding", bytes.Repeat([]byte{0x41}, 20)},         // 20 bytes (4 complete groups)
		{"one_byte_padding", bytes.Repeat([]byte{0x41}, 17)},   // 17 bytes (3 complete groups + 2 bytes)
		{"two_byte_padding", bytes.Repeat([]byte{0x41}, 18)},   // 18 bytes (3 complete groups + 3 bytes)
		{"three_byte_padding", bytes.Repeat([]byte{0x41}, 19)}, // 19 bytes (3 complete groups + 4 bytes)
	}

	for _, tc := range paddingTests {
		encoded := encoder.Encode(tc.data)

		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(encoded)
			}
		})
	}
}

// BenchmarkStdDecoder_DecodeSpecialZ benchmarks the standard decoder with special 'z' character
func BenchmarkStdDecoder_DecodeSpecialZ(b *testing.B) {
	decoder := NewStdDecoder()

	// Test special 'z' character (represents 4 zero bytes)
	specialZData := []string{
		"z",      // Single 'z'
		"zz",     // Two 'z's
		"zzz",    // Three 'z's
		"zzzz",   // Four 'z's
		"zzzzz",  // Five 'z's
		"AzBzCz", // Mixed with other characters
	}

	for _, data := range specialZData {
		b.Run(fmt.Sprintf("special_z_%s", data), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode([]byte(data))
			}
		})
	}
}

// BenchmarkStreamEncoder_Write benchmarks the streaming encoder Write method
func BenchmarkStreamEncoder_Write(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf := &bytes.Buffer{}
				encoder := NewStreamEncoder(buf)
				encoder.Write(data)
				encoder.Close()
			}
		})
	}
}

// BenchmarkStreamEncoder_WriteClose benchmarks the streaming encoder Write + Close combination
func BenchmarkStreamEncoder_WriteClose(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf := &bytes.Buffer{}
				encoder := NewStreamEncoder(buf)
				encoder.Write(data)
				encoder.Close()
			}
		})
	}
}

// BenchmarkStreamEncoder_WriteCloseLarge benchmarks the streaming encoder with large data
func BenchmarkStreamEncoder_WriteCloseLarge(b *testing.B) {
	largeSizes := []int{65536, 262144, 1048576} // 64KB, 256KB, 1MB

	for _, size := range largeSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf := &bytes.Buffer{}
				encoder := NewStreamEncoder(buf)
				encoder.Write(data)
				encoder.Close()
			}
		})
	}
}

// BenchmarkStreamDecoder_Read benchmarks the streaming decoder Read method
func BenchmarkStreamDecoder_Read(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		// Encode the data first
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(encoded)
				decoder := NewStreamDecoder(reader)

				// Read all data
				buf := make([]byte, size)
				decoder.Read(buf)
			}
		})
	}
}

// BenchmarkStreamDecoder_ReadLarge benchmarks the streaming decoder with large data
func BenchmarkStreamDecoder_ReadLarge(b *testing.B) {
	largeSizes := []int{65536, 262144, 1048576} // 64KB, 256KB, 1MB

	for _, size := range largeSizes {
		data := make([]byte, size)
		rand.Read(data)

		// Encode the data first
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(encoded)
				decoder := NewStreamDecoder(reader)

				// Read data in chunks
				chunkSize := 1024
				buf := make([]byte, chunkSize)
				for {
					n, err := decoder.Read(buf)
					if err == io.EOF || n == 0 {
						break
					}
				}
			}
		})
	}
}

// BenchmarkStreamDecoder_ReadChunked benchmarks the streaming decoder with chunked reading
func BenchmarkStreamDecoder_ReadChunked(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		// Encode the data first
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reader := bytes.NewReader(encoded)
				decoder := NewStreamDecoder(reader)

				// Read data in chunks
				chunkSize := 1024
				buf := make([]byte, chunkSize)
				for {
					n, err := decoder.Read(buf)
					if err == io.EOF || n == 0 {
						break
					}
				}
			}
		})
	}
}

// BenchmarkPostScriptStyle benchmarks Base85 encoding/decoding in PostScript style
func BenchmarkPostScriptStyle(b *testing.B) {
	// PostScript-style data (text with special characters)
	postscriptData := []byte(`%!PS-Adobe-3.0
%%Title: Test Document
%%Creator: Base85 Benchmark
%%CreationDate: 2024
%%EndComments
/showpage { def } def
/Times-Roman findfont 12 scalefont setfont
72 720 moveto
(Hello, World!) show
showpage`)

	encoder := NewStdEncoder()
	decoder := NewStdDecoder()
	encoded := encoder.Encode(postscriptData)

	b.Run("encode_postscript", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(postscriptData)
		}
	})

	b.Run("decode_postscript", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})
}

// BenchmarkImageData benchmarks Base85 encoding/decoding with image-like data
func BenchmarkImageData(b *testing.B) {
	// Simulate image data (repeated patterns, some zeros)
	imageData := make([]byte, 1024)
	for i := 0; i < len(imageData); i += 4 {
		imageData[i] = byte(i % 256)         // R
		imageData[i+1] = byte((i + 1) % 256) // G
		imageData[i+2] = byte((i + 2) % 256) // B
		imageData[i+3] = 255                 // A (opaque)
	}

	encoder := NewStdEncoder()
	decoder := NewStdDecoder()
	encoded := encoder.Encode(imageData)

	b.Run("encode_image", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(imageData)
		}
	})

	b.Run("decode_image", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})
}

// BenchmarkErrorConditions benchmarks error handling scenarios
func BenchmarkErrorConditions(b *testing.B) {
	decoder := NewStdDecoder()

	// Test invalid Base85 data
	invalidData := []byte("Invalid!@#$%^&*()")

	b.Run("decode_invalid", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(invalidData)
		}
	})

	// Test incomplete data
	incompleteData := []byte("Incomplete")

	b.Run("decode_incomplete", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(incompleteData)
		}
	})
}

// BenchmarkMemoryAllocation benchmarks memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("alloc_%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				encoder := NewStdEncoder()
				decoder := NewStdDecoder()
				encoded := encoder.Encode(data)
				decoder.Decode(encoded)
			}
		})
	}
}

// BenchmarkStreamingMemoryAllocation benchmarks streaming memory allocation
func BenchmarkStreamingMemoryAllocation(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("stream_alloc_%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Encode
				encodeBuf := &bytes.Buffer{}
				encoder := NewStreamEncoder(encodeBuf)
				encoder.Write(data)
				encoder.Close()

				// Decode
				decoder := NewStreamDecoder(bytes.NewReader(encodeBuf.Bytes()))
				io.Copy(io.Discard, decoder)
			}
		})
	}
}

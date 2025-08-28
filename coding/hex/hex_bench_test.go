package hex

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
	"block_size":      bytes.Repeat([]byte{0x41}, 4), // 4 bytes
	"unicode":         []byte("Hello, 世界! 🌍"),
	"leading_zeros":   append([]byte{0x00, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0x41}, 16)...),
	"all_zeros":       bytes.Repeat([]byte{0x00}, 20),
	"mixed_data":      append([]byte{0x00, 0xFF, 0x41, 0x7F}, bytes.Repeat([]byte{0x42}, 16)...),
	"short_string":    []byte("Short"),
	"block_size_plus": bytes.Repeat([]byte{0x41}, 9), // 9 bytes
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

// BenchmarkStdDecoder_DecodeBlockSizes benchmarks the standard decoder with different block sizes
func BenchmarkStdDecoder_DecodeBlockSizes(b *testing.B) {
	encoder := NewStdEncoder()
	decoder := NewStdDecoder()

	// Test different block sizes (2-byte aligned for hex)
	blockSizes := []int{2, 4, 6, 8, 10, 12, 14, 16}

	for _, size := range blockSizes {
		data := bytes.Repeat([]byte{0x41}, size)
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(encoded)
			}
		})
	}
}

// BenchmarkStdDecoder_DecodeHexPatterns benchmarks the standard decoder with various hex patterns
func BenchmarkStdDecoder_DecodeHexPatterns(b *testing.B) {
	decoder := NewStdDecoder()

	// Test with various hex patterns
	hexPatterns := []string{
		"41424344",         // "ABCD"
		"0001020304050607", // 0x00-0x07
		"FFFEFFFDFFFCFFFB", // 0xFF-0xFB
		"0123456789ABCDEF", // 0x01-0xEF
	}

	for _, pattern := range hexPatterns {
		hexBytes := []byte(pattern)

		b.Run(fmt.Sprintf("hex_%s", pattern), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(hexBytes)
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

// BenchmarkTextData benchmarks Hex encoding/decoding with text data
func BenchmarkTextData(b *testing.B) {
	// Text data with various character types
	textData := []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum.`)

	encoder := NewStdEncoder()
	decoder := NewStdDecoder()
	encoded := encoder.Encode(textData)

	b.Run("encode_text", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(textData)
		}
	})

	b.Run("decode_text", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})
}

// BenchmarkBinaryData benchmarks Hex encoding/decoding with binary data
func BenchmarkBinaryData(b *testing.B) {
	// Binary data with various patterns
	binaryData := make([]byte, 1024)
	for i := 0; i < len(binaryData); i++ {
		binaryData[i] = byte(i % 256)
	}

	encoder := NewStdEncoder()
	decoder := NewStdDecoder()
	encoded := encoder.Encode(binaryData)

	b.Run("encode_binary", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(binaryData)
		}
	})

	b.Run("decode_binary", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})
}

// BenchmarkNetworkData benchmarks Hex encoding/decoding with network-like data
func BenchmarkNetworkData(b *testing.B) {
	// Simulate network packet data
	networkData := []byte{
		0x45, 0x00, 0x00, 0x28, // IP header
		0x00, 0x01, 0x00, 0x00, // IP header continued
		0x40, 0x06, 0x00, 0x00, // TCP flags
		0x7f, 0x00, 0x00, 0x01, // Source IP
		0x7f, 0x00, 0x00, 0x01, // Dest IP
		0x30, 0x39, 0x00, 0x50, // Source/Dest ports
		0x00, 0x00, 0x00, 0x00, // Sequence number
		0x00, 0x00, 0x00, 0x00, // Acknowledgement
	}

	encoder := NewStdEncoder()
	decoder := NewStdDecoder()
	encoded := encoder.Encode(networkData)

	b.Run("encode_network", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(networkData)
		}
	})

	b.Run("decode_network", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})
}

// BenchmarkErrorConditions benchmarks error handling scenarios
func BenchmarkErrorConditions(b *testing.B) {
	decoder := NewStdDecoder()

	// Test invalid hex data (odd length)
	invalidData := []byte("Invalid!@#$%^&*()")

	b.Run("decode_invalid", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(invalidData)
		}
	})

	// Test incomplete data (odd number of hex chars)
	incompleteData := []byte("414243") // "ABC" (odd length)

	b.Run("decode_incomplete", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(incompleteData)
		}
	})

	// Test corrupted data (non-hex characters)
	corruptedData := []byte("41XX4344") // "AXXCD" with invalid chars

	b.Run("decode_corrupted", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(corruptedData)
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

// BenchmarkHexAlphabet benchmarks hex alphabet encoding efficiency
func BenchmarkHexAlphabet(b *testing.B) {
	encoder := NewStdEncoder()

	// Test with data that covers the full hex alphabet
	testBytes := []byte{0x00, 0x01, 0x0F, 0x10, 0x1F, 0x20, 0x2F, 0x30, 0x3F, 0x40, 0x4F, 0x50, 0x5F, 0x60, 0x6F, 0x70, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xAF, 0xB0, 0xBF, 0xC0, 0xCF, 0xD0, 0xDF, 0xE0, 0xEF, 0xF0, 0xFF}

	b.Run("hex_alphabet", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(testBytes)
		}
	})
}

// BenchmarkHexPatterns benchmarks various hex patterns
func BenchmarkHexPatterns(b *testing.B) {
	encoder := NewStdEncoder()

	// Test with various hex patterns
	patterns := [][]byte{
		bytes.Repeat([]byte{0x00}, 16), // All zeros
		bytes.Repeat([]byte{0xFF}, 16), // All ones
		bytes.Repeat([]byte{0xAA}, 16), // Alternating 1010
		bytes.Repeat([]byte{0x55}, 16), // Alternating 0101
		bytes.Repeat([]byte{0x12}, 16), // Repeating pattern
		bytes.Repeat([]byte{0x34}, 16), // Another repeating pattern
	}

	for i, pattern := range patterns {
		b.Run(fmt.Sprintf("pattern_%d", i), func(b *testing.B) {
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				encoder.Encode(pattern)
			}
		})
	}
}

// BenchmarkHexStreaming benchmarks streaming vs standard encoding
func BenchmarkHexStreaming(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("streaming_vs_standard_%d_bytes", size), func(b *testing.B) {
			// Standard encoding
			b.Run("standard", func(b *testing.B) {
				encoder := NewStdEncoder()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					encoder.Encode(data)
				}
			})

			// Streaming encoding
			b.Run("streaming", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					buf := &bytes.Buffer{}
					encoder := NewStreamEncoder(buf)
					encoder.Write(data)
					encoder.Close()
				}
			})
		})
	}
}

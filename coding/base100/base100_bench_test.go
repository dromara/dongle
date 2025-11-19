package base100

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/dromara/dongle/mock"
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

	// Test different block sizes (4-byte aligned)
	blockSizes := []int{4, 8, 12, 16, 20, 24, 28, 32}

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

// BenchmarkStdDecoder_DecodeEmoji benchmarks the standard decoder with emoji-like data
func BenchmarkStdDecoder_DecodeEmoji(b *testing.B) {
	decoder := NewStdDecoder()

	// Test with various emoji patterns
	emojiPatterns := []string{
		"😀😃😄😁",    // 4 emojis
		"🚀🚁🚂🚃🚄",   // 5 emojis
		"🎵🎶🎷🎸🎹🎺",  // 6 emojis
		"🌍🌎🌏🌐🌑🌒🌓", // 7 emojis
	}

	for _, pattern := range emojiPatterns {
		// Convert emoji string to bytes for testing
		emojiBytes := []byte(pattern)

		b.Run(fmt.Sprintf("emoji_%d_chars", len(pattern)), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(emojiBytes)
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
				reader := mock.NewFile(encoded, "test.bin")
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
				reader := mock.NewFile(encoded, "test.bin")
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
				reader := mock.NewFile(encoded, "test.bin")
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

// BenchmarkConvenience_Encode benchmarks the convenience Encode function
func BenchmarkConvenience_Encode(b *testing.B) {
	for name, data := range benchmarkData {
		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Encode(data)
			}
		})
	}
}

// BenchmarkConvenience_Decode benchmarks the convenience Decode function
func BenchmarkConvenience_Decode(b *testing.B) {
	encoder := NewStdEncoder()

	for name, data := range benchmarkData {
		encoded := encoder.Encode(data)

		b.Run(name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Decode(encoded)
			}
		})
	}
}

// BenchmarkConvenience_EncodeSizes benchmarks the convenience Encode function for various sizes
func BenchmarkConvenience_EncodeSizes(b *testing.B) {
	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Encode(data)
			}
		})
	}
}

// BenchmarkConvenience_DecodeSizes benchmarks the convenience Decode function for various sizes
func BenchmarkConvenience_DecodeSizes(b *testing.B) {
	encoder := NewStdEncoder()

	for _, size := range benchmarkSizes {
		data := make([]byte, size)
		rand.Read(data)
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_bytes", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Decode(encoded)
			}
		})
	}
}

// BenchmarkTextData benchmarks Base100 encoding/decoding with text data
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

// BenchmarkBinaryData benchmarks Base100 encoding/decoding with binary data
func BenchmarkBinaryData(b *testing.B) {
	// Binary data with various patterns
	binaryData := make([]byte, 1024)
	for i := range binaryData {
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

// BenchmarkErrorConditions benchmarks error handling scenarios
func BenchmarkErrorConditions(b *testing.B) {
	decoder := NewStdDecoder()

	// Test invalid Base100 data (not 4-byte aligned)
	invalidData := []byte("Invalid!@#$%^&*()")

	b.Run("decode_invalid", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(invalidData)
		}
	})

	// Test incomplete data (partial 4-byte sequence)
	incompleteData := []byte{0xf0, 0x9f, 0x8f} // Only 3 bytes

	b.Run("decode_incomplete", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(incompleteData)
		}
	})

	// Test corrupted data (wrong header bytes)
	corruptedData := []byte{0xf1, 0x9f, 0x8f, 0x80, 0xf0, 0x9e, 0x8e, 0x7f}

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
				decoder := NewStreamDecoder(mock.NewFile(encodeBuf.Bytes(), "test.bin"))
				io.Copy(io.Discard, decoder)
			}
		})
	}
}

// BenchmarkEmojiConversion benchmarks the emoji conversion algorithm
func BenchmarkEmojiConversion(b *testing.B) {
	encoder := NewStdEncoder()

	// Test various byte values to cover the conversion algorithm
	testBytes := []byte{0x00, 0x01, 0x3F, 0x40, 0x7F, 0x80, 0xBF, 0xC0, 0xFF}

	b.Run("emoji_conversion", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(testBytes)
		}
	})
}

// BenchmarkUTF8Sequences benchmarks UTF-8 sequence generation
func BenchmarkUTF8Sequences(b *testing.B) {
	encoder := NewStdEncoder()

	// Test with data that will generate various UTF-8 sequences
	testData := make([]byte, 256)
	for i := range 256 {
		testData[i] = byte(i)
	}

	b.Run("utf8_sequences", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(testData)
		}
	})
}

// BenchmarkStreamingVsStandard benchmarks streaming vs standard performance
func BenchmarkStreamingVsStandard(b *testing.B) {
	data := bytes.Repeat([]byte("Hello, World! "), 100) // ~1.5KB

	b.Run("standard_encoder", func(b *testing.B) {
		encoder := NewStdEncoder()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			encoder.Encode(data)
		}
	})

	b.Run("streaming_encoder", func(b *testing.B) {
		var buf bytes.Buffer
		encoder := NewStreamEncoder(&buf)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf.Reset()
			encoder.Write(data)
			encoder.Close()
		}
	})

	b.Run("standard_decoder", func(b *testing.B) {
		encoder := NewStdEncoder()
		decoder := NewStdDecoder()
		encoded := encoder.Encode(data)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decoder.Decode(encoded)
		}
	})

	b.Run("streaming_decoder", func(b *testing.B) {
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)
		reader := mock.NewFile(encoded, "test.bin")
		decoder := NewStreamDecoder(reader)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			reader.Seek(0, 0)
			io.Copy(io.Discard, decoder)
		}
	})
}

// BenchmarkLargeFileStreaming benchmarks streaming performance for various data sizes
func BenchmarkLargeFileStreaming(b *testing.B) {
	sizes := []int{1024, 10 * 1024, 50 * 1024} // 1KB, 10KB, 50KB

	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i % 256)
		}

		b.Run(fmt.Sprintf("encode_%dKB", size/1024), func(b *testing.B) {
			var buf bytes.Buffer
			encoder := NewStreamEncoder(&buf)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				encoder.Write(data)
				encoder.Close()
			}
		})

		b.Run(fmt.Sprintf("decode_%dKB", size/1024), func(b *testing.B) {
			encoded := NewStdEncoder().Encode(data)
			reader := mock.NewFile(encoded, "test.bin")
			decoder := NewStreamDecoder(reader)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				reader.Seek(0, 0)
				io.Copy(io.Discard, decoder)
			}
		})
	}
}

// BenchmarkStreamingBufferSizes benchmarks streaming performance with different buffer sizes
func BenchmarkStreamingBufferSizes(b *testing.B) {
	data := make([]byte, 20*1024) // 20KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	bufferSizes := []int{256, 512, 1024, 2048} // Reduced from 5 sizes to 4

	for _, bufSize := range bufferSizes {
		b.Run(fmt.Sprintf("buffer_%d", bufSize), func(b *testing.B) {
			var buf bytes.Buffer
			encoder := NewStreamEncoder(&buf)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				// Write in chunks of buffer size
				for j := 0; j < len(data); j += bufSize {
					end := j + bufSize
					if end > len(data) {
						end = len(data)
					}
					encoder.Write(data[j:end])
				}
				encoder.Close()
			}
		})
	}
}

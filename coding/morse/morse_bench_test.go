package morse

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Benchmark data sizes
var benchmarkSizes = []int{16, 64, 256, 1024, 4096, 16384}

// Benchmark data types
var benchmarkData = map[string][]byte{
	"empty":          {},
	"single_char":    []byte("a"),
	"short_word":     []byte("hello"),
	"long_word":      []byte("supercalifragilisticexpialidocious"),
	"numbers":        []byte("1234567890"),
	"punctuation":    []byte("hello,world!"),
	"mixed_case":     []byte("HelloWorld"),
	"repeated":       []byte("aaa"),
	"morse_friendly": []byte("sos"),
	"complex_word":   []byte("internationalization"),
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("random_%d_chars", size), func(b *testing.B) {
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
			// Repeat pattern to reach desired size
			repeated := strings.Repeat(pattern, size/len(pattern)+1)
			data := []byte(repeated[:size])

			b.Run(fmt.Sprintf("%s_%d_chars", pattern, size), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					encoder.Encode(data)
				}
			})
		}
	}
}

// BenchmarkStdEncoder_EncodeMorsePatterns benchmarks the standard encoder with morse-friendly patterns
func BenchmarkStdEncoder_EncodeMorsePatterns(b *testing.B) {
	encoder := NewStdEncoder()

	// Test with patterns that are common in morse code
	morsePatterns := []string{
		"sos", // Short pattern
		"cq",  // Call for any station
		"de",  // From
		"k",   // Over
		"sk",  // End of transmission
		"73",  // Best regards
		"88",  // Love and kisses
	}

	for _, pattern := range morsePatterns {
		data := []byte(pattern)
		b.Run(fmt.Sprintf("morse_%s", pattern), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoder.Encode(data)
			}
		})
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}
		encoded := NewStdEncoder().Encode(data)

		b.Run(fmt.Sprintf("random_%d_chars", size), func(b *testing.B) {
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
			// Repeat pattern to reach desired size
			repeated := strings.Repeat(pattern, size/len(pattern)+1)
			data := []byte(repeated[:size])
			encoded := encoder.Encode(data)

			b.Run(fmt.Sprintf("%s_%d_chars", pattern, size), func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					decoder.Decode(encoded)
				}
			})
		}
	}
}

// BenchmarkStdDecoder_DecodeMorsePatterns benchmarks the standard decoder with morse patterns
func BenchmarkStdDecoder_DecodeMorsePatterns(b *testing.B) {
	decoder := NewStdDecoder()

	// Test with actual morse code patterns
	morsePatterns := []string{
		"... --- ...",       // SOS
		"-.-. --.-",         // CQ
		"-.. .",             // DE
		"-.-",               // K
		"... -.-",           // SK
		"----- --... ...--", // 73
		"---.. ---..",       // 88
	}

	for _, pattern := range morsePatterns {
		data := []byte(pattern)
		b.Run(fmt.Sprintf("morse_%s", strings.ReplaceAll(pattern, " ", "_")), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				decoder.Decode(data)
			}
		})
	}
}

// BenchmarkStreamEncoder_Write benchmarks the streaming encoder Write method
func BenchmarkStreamEncoder_Write(b *testing.B) {
	for _, size := range benchmarkSizes {
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		// Encode the data first
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		// Encode the data first
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		// Encode the data first
		encoder := NewStdEncoder()
		encoded := encoder.Encode(data)

		b.Run(fmt.Sprintf("%d_chars", size), func(b *testing.B) {
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

// BenchmarkTextData benchmarks Morse encoding/decoding with text data
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

// BenchmarkMorsePatterns benchmarks various morse code patterns
func BenchmarkMorsePatterns(b *testing.B) {
	encoder := NewStdEncoder()

	// Test with various morse patterns
	morsePatterns := []string{
		"sos",           // Short pattern
		"cq",            // Call for any station
		"de",            // From
		"k",             // Over
		"sk",            // End of transmission
		"73",            // Best regards
		"88",            // Love and kisses
		"hello",         // Common word
		"world",         // Common word
		"international", // Long word
	}

	for _, pattern := range morsePatterns {
		data := []byte(pattern)
		b.Run(fmt.Sprintf("morse_%s", pattern), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoder.Encode(data)
			}
		})
	}
}

// BenchmarkErrorConditions benchmarks error handling scenarios
func BenchmarkErrorConditions(b *testing.B) {
	decoder := NewStdDecoder()

	// Test invalid morse data (contains spaces)
	invalidData := []byte("... --- ... ---") // SOS with extra separator

	b.Run("decode_invalid", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			decoder.Decode(invalidData)
		}
	})

	// Test corrupted data (invalid morse code)
	corruptedData := []byte("... --- xxx") // SOS with invalid character

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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("alloc_%d_chars", size), func(b *testing.B) {
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
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("stream_alloc_%d_chars", size), func(b *testing.B) {
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

// BenchmarkMorseAlphabet benchmarks morse alphabet encoding efficiency
func BenchmarkMorseAlphabet(b *testing.B) {
	encoder := NewStdEncoder()

	// Test with data that covers the full morse alphabet
	testData := []byte("abcdefghijklmnopqrstuvwxyz0123456789.,?!=+-/")

	b.Run("morse_alphabet", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			encoder.Encode(testData)
		}
	})
}

// BenchmarkMorseStreaming benchmarks streaming vs standard encoding
func BenchmarkMorseStreaming(b *testing.B) {
	for _, size := range benchmarkSizes {
		// Generate random text data
		data := make([]byte, size)
		for i := 0; i < size; i++ {
			data[i] = byte('a' + (i % 26)) // Generate lowercase letters
		}

		b.Run(fmt.Sprintf("streaming_vs_standard_%d_chars", size), func(b *testing.B) {
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

// BenchmarkMorseSeparators benchmarks different separator handling
func BenchmarkMorseSeparators(b *testing.B) {
	encoder := NewStdEncoder()

	// Test with different text patterns
	textPatterns := []string{
		"hello",       // Single word
		"helloworld",  // Concatenated words
		"hello world", // Words with space (should error)
		"hello-world", // Words with hyphen
		"hello_world", // Words with underscore
	}

	for _, pattern := range textPatterns {
		data := []byte(pattern)
		b.Run(fmt.Sprintf("separator_%s", strings.ReplaceAll(pattern, " ", "_")), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encoder.Encode(data)
			}
		})
	}
}

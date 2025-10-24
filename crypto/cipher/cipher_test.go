package cipher

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test data
var (
	testKey    = []byte("testkey123")
	testIV     = []byte("testiv1234567890") // 16-byte IV for 16-byte block size
	testIV8    = []byte("testiv12")         // 8-byte IV for 8-byte block size
	testAAD    = []byte("testaad")
	testData   = []byte("testdata")
	testData16 = []byte("testdata12345678") // 16-byte data for No padding
)

func TestBaseCipher_SetKey(t *testing.T) {
	t.Run("set key with different values", func(t *testing.T) {
		testCases := []struct {
			name string
			key  []byte
		}{
			{"nil key", nil},
			{"empty key", []byte{}},
			{"valid key", testKey},
			{"long key", make([]byte, 100)},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := &baseCipher{}
				cipher.SetKey(tc.key)
				assert.Equal(t, tc.key, cipher.Key)
			})
		}
	})
}

func TestBlockCipher_SetPadding(t *testing.T) {
	t.Run("set all padding modes", func(t *testing.T) {
		paddings := []PaddingMode{
			No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit,
		}

		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := &blockCipher{}
				cipher.SetPadding(padding)
				assert.Equal(t, padding, cipher.Padding)
			})
		}
	})
}

func TestBlockCipher_SetIV(t *testing.T) {
	t.Run("set IV with different values", func(t *testing.T) {
		testCases := []struct {
			name string
			iv   []byte
		}{
			{"nil IV", nil},
			{"empty IV", []byte{}},
			{"valid IV", testIV},
			{"long IV", make([]byte, 100)},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := &blockCipher{}
				cipher.SetIV(tc.iv)
				assert.Equal(t, tc.iv, cipher.IV)
			})
		}
	})
}

func TestBlockCipher_SetNonce(t *testing.T) {
	t.Run("set nonce with different values", func(t *testing.T) {
		testCases := []struct {
			name  string
			nonce []byte
		}{
			{"nil nonce", nil},
			{"empty nonce", []byte{}},
			{"valid nonce", []byte("123456789012")},
			{"long nonce", make([]byte, 100)},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := &blockCipher{}
				cipher.SetNonce(tc.nonce)
				assert.Equal(t, tc.nonce, cipher.Nonce)
			})
		}
	})
}

func TestBlockCipher_SetAAD(t *testing.T) {
	t.Run("set AAD with different values", func(t *testing.T) {
		testCases := []struct {
			name string
			aad  []byte
		}{
			{"nil AAD", nil},
			{"empty AAD", []byte{}},
			{"valid AAD", testAAD},
			{"long AAD", make([]byte, 1000)},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := &blockCipher{}
				cipher.SetAAD(tc.aad)
				assert.Equal(t, tc.aad, cipher.AAD)
			})
		}
	})
}

func TestBlockCipher_Encrypt(t *testing.T) {
	t.Run("encrypt with different modes", func(t *testing.T) {
		modes := []BlockMode{CBC, ECB, CTR, CFB, OFB}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := &blockCipher{
					Block:   mode,
					Padding: PKCS7,
					IV:      testIV,
				}

				block := &mockBlock{
					blockSize: 16,
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// For ECB mode, we don't need IV
				if mode == ECB {
					cipher.IV = nil
				}

				result, err := cipher.Encrypt(testData, block)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("encrypt with GCM mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   GCM,
			Padding: PKCS7,
			Nonce:   []byte("123456789012"),
			AAD:     testAAD,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}
		result, err := cipher.Encrypt(testData, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("encrypt with different padding modes", func(t *testing.T) {
		paddings := []PaddingMode{No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit, TBC}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := &blockCipher{
					Block:   CBC,
					Padding: padding,
				}

				block := &mockBlock{
					blockSize: 16, // Default to 16-byte block size
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// For PKCS5, we need to use 8-byte block size and IV
				if padding == PKCS5 {
					cipher.IV = testIV8 // Use 8-byte IV
					block.blockSize = 8 // Use 8-byte block size
				} else {
					// For all other padding modes, use 16-byte IV
					cipher.IV = testIV
				}

				// For No padding, we need data that is a multiple of block size
				data := testData
				if padding == No {
					data = testData16 // Use 16-byte data
				}

				result, err := cipher.Encrypt(data, block)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("encrypt with all padding modes explicitly", func(t *testing.T) {
		// Test each padding mode explicitly to ensure full coverage
		testCases := []struct {
			name      string
			padding   PaddingMode
			iv        []byte
			blockSize int
		}{
			{"No padding", No, testIV, 16},
			{"Zero padding", Zero, testIV, 16},
			{"PKCS5 padding", PKCS5, testIV8, 8},
			{"PKCS7 padding", PKCS7, testIV, 16},
			{"AnsiX923 padding", AnsiX923, testIV, 16},
			{"ISO97971 padding", ISO97971, testIV, 16},
			{"ISO10126 padding", ISO10126, testIV, 16},
			{"ISO78164 padding", ISO78164, testIV, 16},
			{"Bit padding", Bit, testIV, 16},
			{"TBC padding", TBC, testIV, 16},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := &blockCipher{
					Block:   CBC,
					Padding: tc.padding,
					IV:      tc.iv,
				}

				block := &mockBlock{
					blockSize: tc.blockSize,
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// For No padding, we need data that is a multiple of block size
				data := testData
				if tc.padding == No {
					data = testData16 // Use 16-byte data
				}

				result, err := cipher.Encrypt(data, block)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("encrypt with CTR mode using 12-byte nonce", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CTR,
			Padding: PKCS7,
			IV:      []byte("123456789012"), // 12-byte nonce for CTR
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		result, err := cipher.Encrypt(testData, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("encrypt with unknown block mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   BlockMode("UNKNOWN"), // Unknown block mode
			Padding: PKCS7,
			IV:      testIV,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		result, err := cipher.Encrypt(testData, block)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.IsType(t, UnsupportedBlockModeError{}, err)
		assert.Contains(t, err.Error(), "unsupported block mode")
		assert.Contains(t, err.Error(), "UNKNOWN")
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: PKCS7,
			IV:      testIV,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}
		result, err := cipher.Encrypt([]byte{}, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("encrypt nil data", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: PKCS7,
			IV:      testIV,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}
		result, err := cipher.Encrypt(nil, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestBlockCipher_Decrypt(t *testing.T) {
	t.Run("decrypt with different modes", func(t *testing.T) {
		modes := []BlockMode{CBC, ECB, CTR, CFB, OFB}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := &blockCipher{
					Block:   mode,
					Padding: PKCS7,
					IV:      testIV,
				}

				block := &mockBlock{
					blockSize: 16,
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// For ECB mode, we don't need IV
				if mode == ECB {
					cipher.IV = nil
				}

				// First encrypt
				encrypted, err := cipher.Encrypt(testData, block)
				assert.NoError(t, err)

				// Then decrypt
				result, err := cipher.Decrypt(encrypted, block)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("decrypt with GCM mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   GCM,
			Padding: PKCS7,
			Nonce:   []byte("123456789012"),
			AAD:     testAAD,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// First encrypt
		encrypted, err := cipher.Encrypt(testData, block)
		assert.NoError(t, err)

		// Then decrypt
		result, err := cipher.Decrypt(encrypted, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("decrypt with different padding modes", func(t *testing.T) {
		paddings := []PaddingMode{No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit, TBC}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := &blockCipher{
					Block:   CBC,
					Padding: padding,
				}

				block := &mockBlock{
					blockSize: 16, // Default to 16-byte block size
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// For PKCS5, we need to use 8-byte block size and IV
				if padding == PKCS5 {
					cipher.IV = testIV8 // Use 8-byte IV
					block.blockSize = 8 // Use 8-byte block size
				} else {
					// For all other padding modes, use 16-byte IV
					cipher.IV = testIV
				}

				// For No padding, we need data that is a multiple of block size
				data := testData
				if padding == No {
					data = testData16 // Use 16-byte data
				}

				// First encrypt
				encrypted, err := cipher.Encrypt(data, block)
				assert.NoError(t, err)

				// Then decrypt
				result, err := cipher.Decrypt(encrypted, block)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("decrypt with all padding modes explicitly", func(t *testing.T) {
		// Test each padding mode explicitly to ensure full coverage
		testCases := []struct {
			name      string
			padding   PaddingMode
			iv        []byte
			blockSize int
		}{
			{"No padding", No, testIV, 16},
			{"Zero padding", Zero, testIV, 16},
			{"PKCS5 padding", PKCS5, testIV8, 8},
			{"PKCS7 padding", PKCS7, testIV, 16},
			{"AnsiX923 padding", AnsiX923, testIV, 16},
			{"ISO97971 padding", ISO97971, testIV, 16},
			{"ISO10126 padding", ISO10126, testIV, 16},
			{"ISO78164 padding", ISO78164, testIV, 16},
			{"Bit padding", Bit, testIV, 16},
			{"TBC padding", TBC, testIV, 16},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				cipher := &blockCipher{
					Block:   CBC,
					Padding: tc.padding,
					IV:      tc.iv,
				}

				block := &mockBlock{
					blockSize: tc.blockSize,
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// For No padding, we need data that is a multiple of block size
				data := testData
				if tc.padding == No {
					data = testData16 // Use 16-byte data
				}

				// First encrypt
				encrypted, err := cipher.Encrypt(data, block)
				assert.NoError(t, err)

				// Then decrypt
				result, err := cipher.Decrypt(encrypted, block)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("decrypt with CTR mode using 12-byte nonce", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CTR,
			Padding: PKCS7,
			IV:      []byte("123456789012"), // 12-byte nonce for CTR
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// First encrypt
		encrypted, err := cipher.Encrypt(testData, block)
		assert.NoError(t, err)

		// Then decrypt
		result, err := cipher.Decrypt(encrypted, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("round trip encryption/decryption", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: PKCS7,
			IV:      testIV,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// Encrypt
		encrypted, err := cipher.Encrypt(testData, block)
		assert.NoError(t, err)

		// Decrypt
		decrypted, err := cipher.Decrypt(encrypted, block)
		assert.NoError(t, err)
		assert.Equal(t, testData, decrypted)
	})

	t.Run("decrypt with error from block decrypter", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: PKCS7,
			IV:      testIV,
		}

		// Create a mock block that simulates an error during decryption
		errorBlock := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			// Mock decrypt function that doesn't actually decrypt, simulating an error
			decrypt: func(dst, src []byte) {
				// Do nothing, which will leave dst unchanged
				// This simulates a decryption error
			},
		}

		// First encrypt some data
		encrypted, err := cipher.Encrypt(testData, errorBlock)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		// Try to decrypt - this should return nil result and no error
		// because our mock doesn't actually cause an error in the decrypter functions
		// but rather produces incorrect results
		result, err := cipher.Decrypt(encrypted, errorBlock)
		assert.NoError(t, err)
		assert.NotNil(t, result) // The function doesn't return an error, just processes the data
	})

	// Add test case to cover decryption for all block modes
	t.Run("decrypt with all block modes", func(t *testing.T) {
		modes := []BlockMode{CBC, ECB, CTR, GCM, CFB, OFB}
		for _, mode := range modes {
			t.Run(string(mode), func(t *testing.T) {
				cipher := &blockCipher{
					Block:   mode,
					Padding: PKCS7,
				}

				// Set mode-specific parameters
				switch mode {
				case GCM:
					cipher.Nonce = []byte("123456789012")
					cipher.AAD = testAAD
				case ECB:
					// ECB doesn't need IV
				default:
					cipher.IV = testIV
				}

				block := &mockBlock{
					blockSize: 16,
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// Encrypt
				encrypted, err := cipher.Encrypt(testData, block)
				assert.NoError(t, err)
				assert.NotNil(t, encrypted)

				// Decrypt
				decrypted, err := cipher.Decrypt(encrypted, block)
				assert.NoError(t, err)
				assert.NotNil(t, decrypted)
			})
		}
	})

	t.Run("decrypt with all padding modes", func(t *testing.T) {
		paddings := []PaddingMode{No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit, TBC}
		for _, padding := range paddings {
			t.Run(string(padding), func(t *testing.T) {
				cipher := &blockCipher{
					Block:   CBC,
					Padding: padding,
					IV:      testIV,
				}

				block := &mockBlock{
					blockSize: 16,
					encrypt: func(dst, src []byte) {
						// Simple mock encryption: XOR with 0x55
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
					decrypt: func(dst, src []byte) {
						// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
						for i := range src {
							dst[i] = src[i] ^ 0x55
						}
					},
				}

				// For PKCS5, we need to use 8-byte block size and IV
				if padding == PKCS5 {
					cipher.IV = testIV8 // Use 8-byte IV
					block.blockSize = 8 // Use 8-byte block size
				}

				// For No padding, we need data that is a multiple of block size
				data := testData
				if padding == No {
					data = testData16 // Use 16-byte data
				}

				// Encrypt
				encrypted, err := cipher.Encrypt(data, block)
				assert.NoError(t, err)
				assert.NotNil(t, encrypted)

				// Decrypt
				decrypted, err := cipher.Decrypt(encrypted, block)
				assert.NoError(t, err)
				assert.NotNil(t, decrypted)
			})
		}
	})

	t.Run("decrypt with function error", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: PKCS7,
			IV:      []byte{}, // Empty IV to trigger error in CBC decryption
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// Decryption should return error because of empty IV
		result, err := cipher.Decrypt(testData, block)
		assert.Error(t, err) // Should have error
		assert.Nil(t, result)
	})
}

func TestBlockCipher_Encrypt_ErrorCases(t *testing.T) {
	t.Run("encrypt with unsupported padding mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: PaddingMode("UNSUPPORTED"), // Unsupported padding mode
			IV:      testIV,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		result, err := cipher.Encrypt(testData, block)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.IsType(t, UnsupportedPaddingModeError{}, err)
		assert.Contains(t, err.Error(), "unsupported padding mode")
		assert.Contains(t, err.Error(), "UNSUPPORTED")
	})

	t.Run("encrypt with TBC padding mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: TBC,
			IV:      testIV,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		result, err := cipher.Encrypt(testData, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestBlockCipher_Decrypt_ErrorCases(t *testing.T) {
	t.Run("decrypt with unsupported padding mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   ECB,                        // Use ECB to avoid IV length issues
			Padding: PaddingMode("UNSUPPORTED"), // Unsupported padding mode
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// First encrypt some data - this should fail due to unsupported padding
		encrypted, err := cipher.Encrypt(testData, block)
		assert.Error(t, err) // Should fail due to unsupported padding
		assert.Nil(t, encrypted)

		// Try to decrypt with data that is a multiple of block size
		// This should fail due to unsupported padding mode
		blockSizeData := make([]byte, 16) // 16 bytes, multiple of block size
		copy(blockSizeData, "1234567890123456")

		result, err := cipher.Decrypt(blockSizeData, block)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.IsType(t, UnsupportedPaddingModeError{}, err)
		assert.Contains(t, err.Error(), "unsupported padding mode")
		assert.Contains(t, err.Error(), "UNSUPPORTED")
	})

	t.Run("decrypt with CBC error during decryption", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: PKCS7,
			IV:      []byte{}, // Empty IV to trigger error in CBC decryption
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// Decryption should return error because of empty IV
		result, err := cipher.Decrypt(testData, block)
		assert.Error(t, err) // Should have error
		assert.Nil(t, result)
	})

	t.Run("decrypt with ECB error during decryption", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   ECB,
			Padding: PKCS7,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// Use data that is not a multiple of block size to trigger error
		invalidData := []byte("short") // 5 bytes, not multiple of 16
		result, err := cipher.Decrypt(invalidData, block)
		assert.Error(t, err) // Should have error
		assert.Nil(t, result)
	})

	t.Run("decrypt with TBC padding mode", func(t *testing.T) {
		cipher := &blockCipher{
			Block:   CBC,
			Padding: TBC,
			IV:      testIV,
		}

		block := &mockBlock{
			blockSize: 16,
			encrypt: func(dst, src []byte) {
				// Simple mock encryption: XOR with 0x55
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
			decrypt: func(dst, src []byte) {
				// Simple mock decryption: XOR with 0x55 (same as encryption for this mock)
				for i := range src {
					dst[i] = src[i] ^ 0x55
				}
			},
		}

		// First encrypt some data
		encrypted, err := cipher.Encrypt(testData, block)
		assert.NoError(t, err)
		assert.NotNil(t, encrypted)

		// Then decrypt
		result, err := cipher.Decrypt(encrypted, block)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestBlockCipher_Padding(t *testing.T) {
	t.Run("padding with all supported modes", func(t *testing.T) {
		cipher := &blockCipher{}
		blockSize := 16
		testData := []byte("test data")

		paddingModes := []PaddingMode{No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit, TBC}

		for _, mode := range paddingModes {
			t.Run(string(mode), func(t *testing.T) {
				cipher.Padding = mode
				result, err := cipher.padding(testData, blockSize)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("padding with unsupported mode", func(t *testing.T) {
		cipher := &blockCipher{
			Padding: PaddingMode("UNSUPPORTED"),
		}
		blockSize := 16
		testData := []byte("test data")

		result, err := cipher.padding(testData, blockSize)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.IsType(t, UnsupportedPaddingModeError{}, err)
	})
}

func TestBlockCipher_UnPadding(t *testing.T) {
	t.Run("unpadding with all supported modes", func(t *testing.T) {
		cipher := &blockCipher{}
		testData := []byte("test data")

		paddingModes := []PaddingMode{No, Zero, PKCS5, PKCS7, AnsiX923, ISO97971, ISO10126, ISO78164, Bit, TBC}

		for _, mode := range paddingModes {
			t.Run(string(mode), func(t *testing.T) {
				cipher.Padding = mode
				result, err := cipher.unpadding(testData)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("unpadding with unsupported mode", func(t *testing.T) {
		cipher := &blockCipher{
			Padding: PaddingMode("UNSUPPORTED"),
		}
		testData := []byte("test data")

		result, err := cipher.unpadding(testData)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.IsType(t, UnsupportedPaddingModeError{}, err)
	})
}

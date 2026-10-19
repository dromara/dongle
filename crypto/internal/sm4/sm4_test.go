package sm4

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

// TestNewCipher tests the NewCipher function
func TestNewCipher(t *testing.T) {
	// Test with valid key size
	validKey := make([]byte, KeySize)
	c := NewCipher(validKey)
	if c == nil {
		t.Fatal("NewCipher returned nil for valid key")
	}

	// Test with invalid key size
	invalidKeys := [][]byte{
		make([]byte, KeySize-1),
		make([]byte, KeySize+1),
		nil,
	}

	for _, key := range invalidKeys {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("NewCipher did not panic for invalid key size: %d", len(key))
			}
		}()
		NewCipher(key)
	}
}

// TestBlockSize tests the BlockSize method
func TestBlockSize(t *testing.T) {
	key := make([]byte, KeySize)
	c := NewCipher(key)
	if c.BlockSize() != BlockSize {
		t.Errorf("BlockSize() = %d, want %d", c.BlockSize(), BlockSize)
	}
}

// TestEncrypt tests the Encrypt method
func TestEncrypt(t *testing.T) {
	key := make([]byte, KeySize)
	c := NewCipher(key)

	// Test with valid input
	src := make([]byte, BlockSize)
	dst := make([]byte, BlockSize)

	// Should not panic
	c.Encrypt(dst, src)

	// Test with invalid input size
	shortSrc := make([]byte, BlockSize-1)
	defer func() {
		if r := recover(); r == nil {
			t.Error("Encrypt did not panic for short src")
		}
	}()
	c.Encrypt(dst, shortSrc)

	// Test with invalid output size
	shortDst := make([]byte, BlockSize-1)
	defer func() {
		if r := recover(); r == nil {
			t.Error("Encrypt did not panic for short dst")
		}
	}()
	c.Encrypt(shortDst, src)
}

// TestDecrypt tests the Decrypt method
func TestDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	c := NewCipher(key)

	// Test with valid input
	src := make([]byte, BlockSize)
	dst := make([]byte, BlockSize)

	// Should not panic
	c.Decrypt(dst, src)

	// Test with invalid input size
	shortSrc := make([]byte, BlockSize-1)
	defer func() {
		if r := recover(); r == nil {
			t.Error("Decrypt did not panic for short src")
		}
	}()
	c.Decrypt(dst, shortSrc)

	// Test with invalid output size
	shortDst := make([]byte, BlockSize-1)
	defer func() {
		if r := recover(); r == nil {
			t.Error("Decrypt did not panic for short dst")
		}
	}()
	c.Decrypt(shortDst, src)
}

// TestEncryptDecrypt tests that encryption followed by decryption returns the original plaintext
func TestEncryptDecrypt(t *testing.T) {
	// Test with known test vectors
	testCases := []struct {
		keyHex    string
		plainHex  string
		cipherHex string
	}{
		{
			"0123456789abcdeffedcba9876543210",
			"0123456789abcdeffedcba9876543210",
			"681edf34d206965e86b3e94f536e4246",
		},
	}

	for _, tc := range testCases {
		key, _ := hex.DecodeString(tc.keyHex)
		plaintext, _ := hex.DecodeString(tc.plainHex)
		expected, _ := hex.DecodeString(tc.cipherHex)

		c := NewCipher(key)
		ciphertext := make([]byte, BlockSize)
		c.Encrypt(ciphertext, plaintext)

		if !bytes.Equal(ciphertext, expected) {
			t.Errorf("Encrypt() = %x, want %x", ciphertext, expected)
		}

		// Test decryption
		decrypted := make([]byte, BlockSize)
		c.Decrypt(decrypted, ciphertext)

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Decrypt() = %x, want %x", decrypted, plaintext)
		}
	}

	// Test with random data
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := make([]byte, BlockSize)
	for i := range plaintext {
		plaintext[i] = byte(i + 16)
	}

	c := NewCipher(key)
	ciphertext := make([]byte, BlockSize)
	c.Encrypt(ciphertext, plaintext)

	// Verify ciphertext is different from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Test decryption
	decrypted := make([]byte, BlockSize)
	c.Decrypt(decrypted, ciphertext)

	// Verify decryption matches original plaintext
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt() = %x, want %x", decrypted, plaintext)
	}
}

// TestSBoxTransform tests the sBoxTransform function
func TestSBoxTransform(t *testing.T) {
	// Test with known values
	testCases := []struct {
		input  uint32
		output uint32
	}{
		{0x00000000, 0xd6d6d6d6},
		{0xffffffff, 0x48484848},
	}

	for _, tc := range testCases {
		result := sBoxTransform(tc.input)
		if result != tc.output {
			t.Errorf("sBoxTransform(0x%08x) = 0x%08x, want 0x%08x", tc.input, result, tc.output)
		}
	}

	// Test that the function is deterministic
	input := uint32(0x12345678)
	result1 := sBoxTransform(input)
	result2 := sBoxTransform(input)
	if result1 != result2 {
		t.Error("sBoxTransform is not deterministic")
	}
}

// TestLTransform tests the lTransform function
func TestLTransform(t *testing.T) {
	// Test with known values
	testCases := []struct {
		input  uint32
		output uint32
	}{
		{0x00000000, 0x00000000},
		{0xffffffff, 0xffffffff},
	}

	for _, tc := range testCases {
		result := lTransform(tc.input)
		if result != tc.output {
			t.Errorf("lTransform(0x%08x) = 0x%08x, want 0x%08x", tc.input, result, tc.output)
		}
	}

	// Test that the function is deterministic
	input := uint32(0x12345678)
	result1 := lTransform(input)
	result2 := lTransform(input)
	if result1 != result2 {
		t.Error("lTransform is not deterministic")
	}
}

// TestLPrimeTransform tests the lPrimeTransform function
func TestLPrimeTransform(t *testing.T) {
	// Test with known values
	testCases := []struct {
		input  uint32
		output uint32
	}{
		{0x00000000, 0x00000000},
		{0xffffffff, 0xffffffff},
	}

	for _, tc := range testCases {
		result := lPrimeTransform(tc.input)
		if result != tc.output {
			t.Errorf("lPrimeTransform(0x%08x) = 0x%08x, want 0x%08x", tc.input, result, tc.output)
		}
	}

	// Test that the function is deterministic
	input := uint32(0x12345678)
	result1 := lPrimeTransform(input)
	result2 := lPrimeTransform(input)
	if result1 != result2 {
		t.Error("lPrimeTransform is not deterministic")
	}
}

// TestRotateLeft tests the rotateLeft function
func TestRotateLeft(t *testing.T) {
	testCases := []struct {
		input    uint32
		rotateBy uint
		output   uint32
	}{
		{0x12345678, 0, 0x12345678},
		{0x12345678, 4, 0x23456781},
		{0x12345678, 8, 0x34567812},
		{0x12345678, 16, 0x56781234},
		{0x12345678, 24, 0x78123456},
		{0x12345678, 32, 0x12345678}, // 32 mod 32 = 0
		{0x80000000, 1, 0x00000001},
	}

	for _, tc := range testCases {
		result := rotateLeft(tc.input, tc.rotateBy)
		if result != tc.output {
			t.Errorf("rotateLeft(0x%08x, %d) = 0x%08x, want 0x%08x", tc.input, tc.rotateBy, result, tc.output)
		}
	}
}

// TestExpandKey tests the expandKey function
func TestExpandKey(t *testing.T) {
	// Test with known key
	key := [KeySize]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	rk := expandKey(&key)

	// Check that we get 32 round keys
	if len(rk) != 32 {
		t.Errorf("expandKey() returned %d round keys, want 32", len(rk))
	}

	// Check first few round keys with known values
	expectedFirstKeys := [4]uint32{
		0xf12186f9,
		0x41662b61,
		0x5a6ab19a,
		0x7ba92077,
	}

	for i, expected := range expectedFirstKeys {
		if rk[i] != expected {
			t.Errorf("expandKey() rk[%d] = 0x%08x, want 0x%08x", i, rk[i], expected)
		}
	}
}

// TestEncryptRounds tests the encryptRounds function
func TestEncryptRounds(t *testing.T) {
	// Test with known values
	key := [KeySize]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	x := [4]uint32{0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210}

	encryptRounds(&x, &key)

	// Check result with known values
	expected := [4]uint32{0x681edf34, 0xd206965e, 0x86b3e94f, 0x536e4246}
	for i, exp := range expected {
		if x[i] != exp {
			t.Errorf("encryptRounds() x[%d] = 0x%08x, want 0x%08x", i, x[i], exp)
		}
	}
}

// TestDecryptRounds tests the decryptRounds function
func TestDecryptRounds(t *testing.T) {
	// Test with known values
	key := [KeySize]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	// Start with known ciphertext
	x := [4]uint32{0x681edf34, 0xd206965e, 0x86b3e94f, 0x536e4246}

	decryptRounds(&x, &key)

	// Check result with known plaintext
	expected := [4]uint32{0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210}
	for i, exp := range expected {
		if x[i] != exp {
			t.Errorf("decryptRounds() x[%d] = 0x%08x, want 0x%08x", i, x[i], exp)
		}
	}
}

// TestCipherInterface ensures sm4Cipher implements the cipher.Block interface
func TestCipherInterface(t *testing.T) {
	var _ cipher.Block = &sm4Cipher{}

	key := make([]byte, KeySize)
	c := NewCipher(key)

	// Test that it implements the interface correctly
	if c.BlockSize() != BlockSize {
		t.Errorf("BlockSize() = %d, want %d", c.BlockSize(), BlockSize)
	}
}

// TestMultipleBlocks tests encryption and decryption of multiple blocks
func TestMultipleBlocks(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	c := NewCipher(key)

	// Test multiple blocks
	blocks := 5
	plaintext := make([]byte, blocks*BlockSize)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ciphertext := make([]byte, blocks*BlockSize)
	for i := 0; i < blocks; i++ {
		c.Encrypt(ciphertext[i*BlockSize:(i+1)*BlockSize], plaintext[i*BlockSize:(i+1)*BlockSize])
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Decrypt
	decrypted := make([]byte, blocks*BlockSize)
	for i := 0; i < blocks; i++ {
		c.Decrypt(decrypted[i*BlockSize:(i+1)*BlockSize], ciphertext[i*BlockSize:(i+1)*BlockSize])
	}

	// Verify decryption matches original plaintext
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text should match original plaintext")
	}
}

// TestInPlaceEncryptionDecryption tests that encryption and decryption work in-place
func TestInPlaceEncryptionDecryption(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	c := NewCipher(key)

	// Test in-place encryption
	plaintext := make([]byte, BlockSize)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// Make a copy for comparison
	original := make([]byte, BlockSize)
	copy(original, plaintext)

	// Encrypt in-place
	c.Encrypt(plaintext, plaintext)

	// Verify it changed
	if bytes.Equal(plaintext, original) {
		t.Error("In-place encryption should change the data")
	}

	// Decrypt in-place
	c.Decrypt(plaintext, plaintext)

	// Verify it's back to original
	if !bytes.Equal(plaintext, original) {
		t.Error("In-place decryption should restore original data")
	}
}

// TestEncryptPanic tests the panic cases in Encrypt
func TestEncryptPanic(t *testing.T) {
	key := make([]byte, KeySize)
	c := NewCipher(key)

	// Test with short src
	shortSrc := make([]byte, BlockSize-1)
	dst := make([]byte, BlockSize)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Encrypt did not panic for short src")
		} else if r != "crypto/sm4: input not full block" {
			t.Errorf("Encrypt panicked with wrong message: %v", r)
		}
	}()
	c.Encrypt(dst, shortSrc)
}

// TestDecryptPanic tests the panic cases in Decrypt
func TestDecryptPanic(t *testing.T) {
	key := make([]byte, KeySize)
	c := NewCipher(key)

	// Test with short src
	shortSrc := make([]byte, BlockSize-1)
	dst := make([]byte, BlockSize)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Decrypt did not panic for short src")
		} else if r != "crypto/sm4: input not full block" {
			t.Errorf("Decrypt panicked with wrong message: %v", r)
		}
	}()
	c.Decrypt(dst, shortSrc)
}

// TestEncryptPanicShortDst tests the panic case when dst is too short in Encrypt
func TestEncryptPanicShortDst(t *testing.T) {
	key := make([]byte, KeySize)
	c := NewCipher(key)

	src := make([]byte, BlockSize)
	shortDst := make([]byte, BlockSize-1)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Encrypt did not panic for short dst")
		} else if r != "crypto/sm4: output not full block" {
			t.Errorf("Encrypt panicked with wrong message: %v", r)
		}
	}()
	c.Encrypt(shortDst, src)
}

// TestDecryptPanicShortDst tests the panic case when dst is too short in Decrypt
func TestDecryptPanicShortDst(t *testing.T) {
	key := make([]byte, KeySize)
	c := NewCipher(key)

	src := make([]byte, BlockSize)
	shortDst := make([]byte, BlockSize-1)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Decrypt did not panic for short dst")
		} else if r != "crypto/sm4: output not full block" {
			t.Errorf("Decrypt panicked with wrong message: %v", r)
		}
	}()
	c.Decrypt(shortDst, src)
}

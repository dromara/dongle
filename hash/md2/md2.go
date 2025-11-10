// Package md2 implements the MD2 hash algorithm as defined in RFC 1319.
// MD2 is a cryptographic hash function that produces a 128-bit (16-byte) hash value.
// Note: MD2 is considered cryptographically broken and should not be used for security purposes.
package md2

import (
	"hash"
)

// HashSize is the size of an MD2 hash in bytes.
const HashSize = 16

// BlockSize is the block size of the MD2 hash in bytes.
const BlockSize = 16

// Precomputed padding arrays for all possible padding sizes (1-16 bytes)
// This avoids allocating padding memory on every Sum() call
var paddingTable = [BlockSize][BlockSize]byte{
	{1},
	{2, 2},
	{3, 3, 3},
	{4, 4, 4, 4},
	{5, 5, 5, 5, 5},
	{6, 6, 6, 6, 6, 6},
	{7, 7, 7, 7, 7, 7, 7},
	{8, 8, 8, 8, 8, 8, 8, 8},
	{9, 9, 9, 9, 9, 9, 9, 9, 9},
	{10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
	{11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11},
	{12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
	{13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13},
	{14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14},
	{15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
	{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
}

// S-box used in MD2 algorithm (RFC 1319)
// This substitution table is used for the non-linear transformation
// that provides the cryptographic strength of the MD2 algorithm
var sBox = [256]byte{
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
}

// digest represents the partial evaluation of an MD2 hash.
type digest struct {
	// digest stores the current hash state
	digest [BlockSize]byte
	// state is the internal state buffer used during hash computation
	state [48]byte
	// x is the input buffer for accumulating data before processing
	x [BlockSize]byte
	// nx is the number of bytes currently in the input buffer
	nx uint8
}

// Reset resets the hash to its initial state.
func (d *digest) Reset() {
	// Use clear for better performance on modern Go versions
	clear(d.digest[:])
	clear(d.state[:])
	clear(d.x[:])
	d.nx = 0
}

// New returns a new hash.Hash computing the MD2 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Size returns the size of the hash in bytes.
func (d *digest) Size() int { return HashSize }

// BlockSize returns the block size of the hash in bytes.
func (d *digest) BlockSize() int { return BlockSize }

// Write adds the contents of p to the running hash.
// It never returns an error.
func (d *digest) Write(p []byte) (n int, err error) {
	n = len(p)

	// If we have something left in the buffer
	if d.nx > 0 {
		nu := uint8(n)

		// try to copy the rest n bytes free of the buffer into the buffer than hash the buffer
		if (nu + d.nx) > BlockSize {
			nu = BlockSize - d.nx
		}

		// Use copy for better performance
		copy(d.x[d.nx:], p[:nu])
		d.nx += nu

		// if we have exactly 1 block in the buffer than hash that block
		if d.nx == BlockSize {
			d.block(d.x[:])
			d.nx = 0
		}

		p = p[nu:]
	}

	m := len(p) / BlockSize
	// For the rest, try hashing by the block size
	for i := 0; i < m; i++ {
		d.block(p[:BlockSize])
		p = p[BlockSize:]
	}

	// Then stuff the rest that doesn't add up to a block to the buffer
	if len(p) > 0 {
		d.nx = uint8(copy(d.x[:], p))
	}

	return
}

// Sum appends the current hash to in and returns the resulting slice.
// It does not change the underlying hash state.
func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	dig := new(digest)
	*dig = *d

	// Padding. Add padding bytes to make the total length a multiple of BlockSize.
	paddingSize := BlockSize - dig.nx

	// Use precomputed padding table to avoid allocation
	dig.Write(paddingTable[paddingSize-1][:paddingSize])
	dig.Write(dig.digest[:])
	return append(in, dig.state[:HashSize]...)
}

// block processes a single block of data according to the MD2 algorithm.
// This is the core hash function that performs the actual MD2 computation.
// The function implements the three-step process defined in RFC 1319:
// 1. Copy input block to state buffer and XOR with current state
// 2. Process state buffer through S-box substitution
// 3. Update digest using input block and current digest
func (d *digest) block(p []byte) {
	var t uint8

	// Step 1: Copy input block to state buffer and compute checksum
	// Copy the 16-byte input block to positions 16-31 of the state buffer
	// Also compute XOR of input block with current state for positions 32-47
	// Use copy for better performance on the first part
	copy(d.state[16:32], p[:16])

	// Manually compute XOR for state[32:48]
	for i := 0; i < 16; i++ {
		d.state[i+32] = p[i] ^ d.state[i] // XOR input with current state for state[32:48]
	}

	// Step 2: Process state buffer through S-box substitution
	// Perform 18 rounds of S-box substitution on the entire 48-byte state buffer
	// Each round uses the current value of t as an index into the S-box
	for i := 0; i < 18; i++ {
		for j := 0; j < 48; j++ {
			d.state[j] = d.state[j] ^ sBox[t] // XOR state byte with S-box value
			t = d.state[j]                    // Update t with the new state value
		}
		t = t + uint8(i) // Add round number to t for the next round
	}

	// Step 3: Update digest using input block and current digest
	// Initialize t with the last byte of the current digest
	// This creates a feedback mechanism that incorporates the current hash state
	t = d.digest[15]

	// Process each byte of the input block to update the digest
	// Use the input byte XORed with t as an index into the S-box
	for i := 0; i < 16; i++ {
		d.digest[i] = d.digest[i] ^ sBox[p[i]^t] // XOR digest byte with S-box value
		t = d.digest[i]                          // Update t with the new digest value
	}
}

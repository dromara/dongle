// Package sm3 implements the SM3 hash algorithm as defined in GB/T 32918.1-2016.
//
// SM3 is a Chinese national standard hash algorithm that produces a 256-bit hash value.
// It is designed to be secure and efficient for various cryptographic applications.
package sm3

import (
	"encoding/binary"
	"hash"
)

const (
	// Size is the size of an SM3 checksum in bytes.
	Size = 32
	// BlockSize is the blocksize of SM3 in bytes.
	BlockSize = 64
)

// digest represents the partial evaluation of an SM3 checksum.
type digest struct {
	h      [8]uint32 // hash values
	length uint64    // length of the message in bits
	data   []byte    // unprocessed message data
}

// New returns a new hash.Hash computing the SM3 checksum.
func New() hash.Hash {
	d := &digest{}
	d.Reset()
	return d
}

// Reset resets the digest to its initial state.
func (d *digest) Reset() {
	// Reset digest to initial values
	d.h[0] = 0x7380166f
	d.h[1] = 0x4914b2b9
	d.h[2] = 0x172442d7
	d.h[3] = 0xda8a0600
	d.h[4] = 0xa96f30bc
	d.h[5] = 0x163138aa
	d.h[6] = 0xe38dee4d
	d.h[7] = 0xb0fb0e4e

	d.length = 0
	d.data = []byte{}
}

// Size returns the number of bytes Sum will return.
func (d *digest) Size() int { return Size }

// BlockSize returns the hash's underlying block size.
func (d *digest) BlockSize() int { return BlockSize }

// Write adds more data to the running hash.
func (d *digest) Write(p []byte) (int, error) {
	toWrite := len(p)
	d.length += uint64(len(p) * 8)
	data := append(d.data, p...)
	d.update(data)
	// Update unprocessed data
	d.data = data[len(data)/BlockSize*BlockSize:]
	return toWrite, nil
}

// Sum appends the current hash to b and returns the resulting slice.
func (d *digest) Sum(in []byte) []byte {
	_, _ = d.Write(in)
	data := d.update2(d.pad())

	// Save hash to output slice
	needed := d.Size()
	if cap(in)-len(in) < needed {
		newIn := make([]byte, len(in), len(in)+needed)
		copy(newIn, in)
		in = newIn
	}
	out := in[len(in) : len(in)+needed]
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], data[i])
	}
	return out
}

// pad performs message padding according to SM3 standard.
func (d *digest) pad() []byte {
	data := d.data
	data = append(data, 0x80) // Append '1' bit
	blockSize := 64           // Block size in bytes

	for len(data)%blockSize != 56 {
		data = append(data, 0x00)
	}
	// Append message length in bits
	data = append(data, uint8(d.length>>56&0xff))
	data = append(data, uint8(d.length>>48&0xff))
	data = append(data, uint8(d.length>>40&0xff))
	data = append(data, uint8(d.length>>32&0xff))
	data = append(data, uint8(d.length>>24&0xff))
	data = append(data, uint8(d.length>>16&0xff))
	data = append(data, uint8(d.length>>8&0xff))
	data = append(data, uint8(d.length>>0&0xff))

	return data
}

// update processes message blocks and updates the digest.
func (d *digest) update(msg []byte) {
	var w [68]uint32
	var w1 [64]uint32

	a, b, c, dd, e, f, g, h := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]

	for len(msg) >= 64 {
		// Convert bytes to words
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[4*i : 4*(i+1)])
		}

		// Message expansion
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^leftRotate(w[i-3], 15)) ^ leftRotate(w[i-13], 7) ^ w[i-6]
		}

		// Calculate W1 array
		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		// Initialize working variables
		A, B, C, D, E, F, G, H := a, b, c, dd, e, f, g, h

		// First 16 rounds
		for i := 0; i < 16; i++ {
			SS1 := leftRotate(leftRotate(A, 12)+E+leftRotate(0x79cc4519, uint32(i)), 7)
			SS2 := SS1 ^ leftRotate(A, 12)
			TT1 := ff0(A, B, C) + D + SS2 + w1[i]
			TT2 := gg0(E, F, G) + H + SS1 + w[i]
			D = C
			C = leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = leftRotate(F, 19)
			F = E
			E = p0(TT2)
		}

		// Last 48 rounds
		for i := 16; i < 64; i++ {
			SS1 := leftRotate(leftRotate(A, 12)+E+leftRotate(0x7a879d8a, uint32(i)), 7)
			SS2 := SS1 ^ leftRotate(A, 12)
			TT1 := ff1(A, B, C) + D + SS2 + w1[i]
			TT2 := gg1(E, F, G) + H + SS1 + w[i]
			D = C
			C = leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = leftRotate(F, 19)
			F = E
			E = p0(TT2)
		}

		// Update digest using XOR
		a ^= A
		b ^= B
		c ^= C
		dd ^= D
		e ^= E
		f ^= F
		g ^= G
		h ^= H

		msg = msg[64:]
	}

	// Update final digest
	d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7] = a, b, c, dd, e, f, g, h
}

// update2 processes message blocks and returns the final digest.
func (d *digest) update2(msg []byte) [8]uint32 {
	var w [68]uint32
	var w1 [64]uint32

	a, b, c, dd, e, f, g, h := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]

	for len(msg) >= 64 {
		// Convert bytes to words
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(msg[4*i : 4*(i+1)])
		}

		// Message expansion
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^leftRotate(w[i-3], 15)) ^ leftRotate(w[i-13], 7) ^ w[i-6]
		}

		// Calculate W1 array
		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		// Initialize working variables
		A, B, C, D, E, F, G, H := a, b, c, dd, e, f, g, h

		// First 16 rounds
		for i := 0; i < 16; i++ {
			SS1 := leftRotate(leftRotate(A, 12)+E+leftRotate(0x79cc4519, uint32(i)), 7)
			SS2 := SS1 ^ leftRotate(A, 12)
			TT1 := ff0(A, B, C) + D + SS2 + w1[i]
			TT2 := gg0(E, F, G) + H + SS1 + w[i]
			D = C
			C = leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = leftRotate(F, 19)
			F = E
			E = p0(TT2)
		}

		// Last 48 rounds
		for i := 16; i < 64; i++ {
			SS1 := leftRotate(leftRotate(A, 12)+E+leftRotate(0x7a879d8a, uint32(i)), 7)
			SS2 := SS1 ^ leftRotate(A, 12)
			TT1 := ff1(A, B, C) + D + SS2 + w1[i]
			TT2 := gg1(E, F, G) + H + SS1 + w[i]
			D = C
			C = leftRotate(B, 9)
			B = A
			A = TT1
			H = G
			G = leftRotate(F, 19)
			F = E
			E = p0(TT2)
		}

		// Update digest using XOR
		a ^= A
		b ^= B
		c ^= C
		dd ^= D
		e ^= E
		f ^= F
		g ^= G
		h ^= H

		msg = msg[64:]
	}
	return [8]uint32{a, b, c, dd, e, f, g, h}
}

// Helper functions

// leftRotate performs left rotation of x by i bits.
func leftRotate(x uint32, i uint32) uint32 {
	return x<<(i%32) | x>>(32-i%32)
}

// ff0 implements the first 16 rounds of the FF function.
func ff0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

// ff1 implements the last 48 rounds of the FF function.
func ff1(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

// gg0 implements the first 16 rounds of the GG function.
func gg0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

// gg1 implements the last 48 rounds of the GG function.
func gg1(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

// p0 implements the P0 function.
func p0(x uint32) uint32 {
	return x ^ leftRotate(x, 9) ^ leftRotate(x, 17)
}

// p1 implements the P1 function.
func p1(x uint32) uint32 {
	return x ^ leftRotate(x, 15) ^ leftRotate(x, 23)
}

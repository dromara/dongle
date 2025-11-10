package sm2curve

import (
	"encoding/binary"
	"math/big"
	"math/bits"
)

// felem represents a field element in the SM2 prime field.
// SM2 uses prime p = 2^256 - 2^224 - 2^96 + 2^64 - 1
// We represent elements as [4]uint64 in little-endian order.
type felem [4]uint64

// sm2P is the SM2 prime modulus: FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
var sm2P = felem{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF}

// sm2P2 is 2*p for faster modular reduction
var sm2P2 = felem{0xFFFFFFFFFFFFFFFE, 0xFFFFFFFE00000001, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFDFFFFFFFF}

// felemFromBig converts a big.Int to a field element.
// Returns zero if x is nil or negative.
func felemFromBig(x *big.Int) felem {
	var out felem
	if x == nil || x.Sign() < 0 {
		return out
	}

	// Reduce modulo p first if needed
	tmp := x
	if x.Cmp(sm2PBig) >= 0 {
		tmp = new(big.Int).Mod(x, sm2PBig)
	}

	bytes := tmp.Bytes()

	// Pad to 32 bytes if needed
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		bytes = padded
	}

	// Convert from big-endian bytes to limbs
	// bytes is big-endian: [0]=MSB, [31]=LSB
	// out[0] = least significant limb, out[3] = most significant limb
	out[0] = binary.BigEndian.Uint64(bytes[24:32]) // LSB limb
	out[1] = binary.BigEndian.Uint64(bytes[16:24])
	out[2] = binary.BigEndian.Uint64(bytes[8:16])
	out[3] = binary.BigEndian.Uint64(bytes[0:8]) // MSB limb

	return out
}

// toBig converts a field element to a big.Int.
func (e *felem) toBig() *big.Int {
	bytes := make([]byte, 32)
	// Convert limbs to big-endian bytes
	// e[0] = LSB limb, e[3] = MSB limb
	binary.BigEndian.PutUint64(bytes[24:32], e[0]) // LSB
	binary.BigEndian.PutUint64(bytes[16:24], e[1])
	binary.BigEndian.PutUint64(bytes[8:16], e[2])
	binary.BigEndian.PutUint64(bytes[0:8], e[3]) // MSB
	return new(big.Int).SetBytes(bytes)
}

// felemZero returns a zero field element.
func felemZero() felem {
	return felem{}
}

// felemOne returns the field element 1.
func felemOne() felem {
	return felem{1, 0, 0, 0}
}

// felemIsZero returns true if e is zero.
func (e *felem) isZero() bool {
	return e[0]|e[1]|e[2]|e[3] == 0
}

// felemAdd computes out = a + b mod p.
func felemAdd(out, a, b *felem) {
	var carry uint64
	out[0], carry = bits.Add64(a[0], b[0], 0)
	out[1], carry = bits.Add64(a[1], b[1], carry)
	out[2], carry = bits.Add64(a[2], b[2], carry)
	out[3], carry = bits.Add64(a[3], b[3], carry)

	// If carry, we have overflow (result >= 2^256)
	// We need to reduce: subtract p until result < p
	// Since result < 2^256 + 2^256 = 2^257, we need at most 2 subtractions
	if carry != 0 {
		// Result is >= 2^256, so definitely >= p
		// Subtract p once
		var borrow uint64
		out[0], borrow = bits.Sub64(out[0], sm2P[0], 0)
		out[1], borrow = bits.Sub64(out[1], sm2P[1], borrow)
		out[2], borrow = bits.Sub64(out[2], sm2P[2], borrow)
		out[3], borrow = bits.Sub64(out[3], sm2P[3], borrow)
		// After subtraction, we consumed the carry, so we're back in range [0, 2^256)
	}

	// Now apply normal reduction in case result is still >= p
	felemReduce(out)
}

// felemSub computes out = a - b mod p.
func felemSub(out, a, b *felem) {
	var borrow uint64
	out[0], borrow = bits.Sub64(a[0], b[0], 0)
	out[1], borrow = bits.Sub64(a[1], b[1], borrow)
	out[2], borrow = bits.Sub64(a[2], b[2], borrow)
	out[3], borrow = bits.Sub64(a[3], b[3], borrow)

	// If borrow, add p
	if borrow != 0 {
		var carry uint64
		out[0], carry = bits.Add64(out[0], sm2P[0], 0)
		out[1], carry = bits.Add64(out[1], sm2P[1], carry)
		out[2], carry = bits.Add64(out[2], sm2P[2], carry)
		out[3], _ = bits.Add64(out[3], sm2P[3], carry)
	}
}

// felemReduce reduces e modulo p if e >= p.
// This is a constant-time conditional subtraction.
func felemReduce(e *felem) {
	// Compute e - p
	var tmp felem
	var borrow uint64
	tmp[0], borrow = bits.Sub64(e[0], sm2P[0], 0)
	tmp[1], borrow = bits.Sub64(e[1], sm2P[1], borrow)
	tmp[2], borrow = bits.Sub64(e[2], sm2P[2], borrow)
	tmp[3], borrow = bits.Sub64(e[3], sm2P[3], borrow)

	// If no borrow, e >= p, so use tmp; otherwise keep e
	// mask = 0 if borrow (e < p), 0xFFFFFFFFFFFFFFFF if no borrow (e >= p)
	mask := uint64(0) - (1 - borrow)
	e[0] = (tmp[0] & mask) | (e[0] & ^mask)
	e[1] = (tmp[1] & mask) | (e[1] & ^mask)
	e[2] = (tmp[2] & mask) | (e[2] & ^mask)
	e[3] = (tmp[3] & mask) | (e[3] & ^mask)
}

// felemMul computes out = a * b mod p.
// This uses schoolbook multiplication followed by reduction.
func felemMul(out, a, b *felem) {
	// Full 512-bit product
	var p [8]uint64

	// Schoolbook multiplication
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(a[i], b[j])
			p[i+j], carry = bits.Add64(p[i+j], lo, carry)
			p[i+j+1], carry = bits.Add64(p[i+j+1], hi, carry)
			if carry != 0 {
				for k := i + j + 2; k < 8; k++ {
					p[k], carry = bits.Add64(p[k], carry, 0)
					if carry == 0 {
						break
					}
				}
			}
		}
	}

	// Reduce 512-bit product modulo p
	felemReduceCarry(out, &p)
}

// felemSquare computes out = a^2 mod p.
// This is optimized for squaring.
func felemSquare(out, a *felem) {
	felemMul(out, a, a)
}

// felemReduceCarry reduces a 512-bit value modulo p.
// SM2 prime: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
// So 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
func felemReduceCarry(out *felem, p *[8]uint64) {
	// For now, use big.Int for correctness. Can optimize later with
	// fast reduction specific to SM2's prime structure.
	bytes := make([]byte, 64)

	// Convert limbs to big-endian bytes
	// p[0] = LSB limb, p[7] = MSB limb
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(bytes[56-i*8:64-i*8], p[i])
	}

	tmp := new(big.Int).SetBytes(bytes)
	tmp.Mod(tmp, sm2PBig)

	*out = felemFromBig(tmp)
}

// felemNeg computes out = -a mod p.
func felemNeg(out, a *felem) {
	if a.isZero() {
		*out = felemZero()
		return
	}
	felemSub(out, &sm2P, a)
}

// felemInv computes out = a^(-1) mod p using Fermat's little theorem.
// For prime p, a^(-1) ≡ a^(p-2) (mod p).
// This is not constant-time but acceptable for non-secret data.
func felemInv(out, a *felem) {
	// Use big.Int for inversion (can be optimized later)
	aBig := a.toBig()
	if aBig.Sign() == 0 {
		*out = felemZero()
		return
	}
	inv := new(big.Int).ModInverse(aBig, sm2PBig)
	*out = felemFromBig(inv)
}

// sm2PBig is the SM2 prime as a big.Int for compatibility.
var sm2PBig = func() *big.Int {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	return p
}()

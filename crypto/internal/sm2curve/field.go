package sm2curve

import (
	"encoding/binary"
	"math/big"
	"math/bits"
)

// prime is the SM2 field prime: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
// Stored as 4 limbs in little-endian order (limbs[0] is LSB).
var prime = field{
	limbs: [4]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF},
}

// field represents an element in the SM2 finite field.
// Elements are stored as 4 × 64-bit limbs in little-endian order.
type field struct {
	limbs [4]uint64 // Little-endian: limbs[0] is the least significant
}

// isZero returns true if the field element is zero.
func (f *field) isZero() bool {
	return f.limbs[0]|f.limbs[1]|f.limbs[2]|f.limbs[3] == 0
}

// add computes f = (a + b) mod p.
func (f *field) add(a, b *field) {
	var carry uint64
	f.limbs[0], carry = bits.Add64(a.limbs[0], b.limbs[0], 0)
	f.limbs[1], carry = bits.Add64(a.limbs[1], b.limbs[1], carry)
	f.limbs[2], carry = bits.Add64(a.limbs[2], b.limbs[2], carry)
	f.limbs[3], carry = bits.Add64(a.limbs[3], b.limbs[3], carry)

	// Handle overflow: if carry, result >= 2^256, so subtract p
	if carry != 0 {
		var borrow uint64
		f.limbs[0], borrow = bits.Sub64(f.limbs[0], prime.limbs[0], 0)
		f.limbs[1], borrow = bits.Sub64(f.limbs[1], prime.limbs[1], borrow)
		f.limbs[2], borrow = bits.Sub64(f.limbs[2], prime.limbs[2], borrow)
		f.limbs[3], borrow = bits.Sub64(f.limbs[3], prime.limbs[3], borrow)
	}

	// Final conditional reduction if result >= p
	f.reduce256()
}

// sub computes f = (a - b) mod p.
func (f *field) sub(a, b *field) {
	var borrow uint64
	f.limbs[0], borrow = bits.Sub64(a.limbs[0], b.limbs[0], 0)
	f.limbs[1], borrow = bits.Sub64(a.limbs[1], b.limbs[1], borrow)
	f.limbs[2], borrow = bits.Sub64(a.limbs[2], b.limbs[2], borrow)
	f.limbs[3], borrow = bits.Sub64(a.limbs[3], b.limbs[3], borrow)

	// Handle underflow: if borrow, add p to make result positive
	if borrow != 0 {
		var carry uint64
		f.limbs[0], carry = bits.Add64(f.limbs[0], prime.limbs[0], 0)
		f.limbs[1], carry = bits.Add64(f.limbs[1], prime.limbs[1], carry)
		f.limbs[2], carry = bits.Add64(f.limbs[2], prime.limbs[2], carry)
		f.limbs[3], _ = bits.Add64(f.limbs[3], prime.limbs[3], carry)
	}
}

// mul computes f = (a * b) mod p using schoolbook multiplication.
func (f *field) mul(a, b *field) {
	// Compute full 512-bit product
	var p [8]uint64

	// Schoolbook multiplication
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(a.limbs[i], b.limbs[j])
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
	f.reduce512(&p)
}

// neg computes f = (-a) mod p.
func (f *field) neg(a *field) {
	if a.isZero() {
		*f = field{}
		return
	}
	f.sub(&prime, a)
}

// inv computes f = a^(-1) mod p.
// Uses big.Int.ModInverse (not constant-time).
func (f *field) inv(a *field) {
	aBig := toBigInt(a)
	if aBig.Sign() == 0 {
		*f = field{}
		return
	}
	inv := new(big.Int).ModInverse(aBig, toBigInt(&prime))
	*f = *fromBigInt(inv)
}

// reduce256 conditionally subtracts p if f >= p (constant-time).
func (f *field) reduce256() {
	var tmp field
	var borrow uint64
	tmp.limbs[0], borrow = bits.Sub64(f.limbs[0], prime.limbs[0], 0)
	tmp.limbs[1], borrow = bits.Sub64(f.limbs[1], prime.limbs[1], borrow)
	tmp.limbs[2], borrow = bits.Sub64(f.limbs[2], prime.limbs[2], borrow)
	tmp.limbs[3], borrow = bits.Sub64(f.limbs[3], prime.limbs[3], borrow)

	// Constant-time select: use tmp if f >= p, otherwise keep f
	mask := uint64(0) - (1 - borrow)
	f.limbs[0] = (tmp.limbs[0] & mask) | (f.limbs[0] & ^mask)
	f.limbs[1] = (tmp.limbs[1] & mask) | (f.limbs[1] & ^mask)
	f.limbs[2] = (tmp.limbs[2] & mask) | (f.limbs[2] & ^mask)
	f.limbs[3] = (tmp.limbs[3] & mask) | (f.limbs[3] & ^mask)
}

// reduce512 reduces a 512-bit value to a field element mod p.
// Currently uses big.Int; TODO: implement fast reduction for SM2 prime.
func (f *field) reduce512(p *[8]uint64) {
	bytes := make([]byte, 64)

	// Convert limbs to big-endian bytes
	// p[0] = LSB limb, p[7] = MSB limb
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(bytes[56-i*8:64-i*8], p[i])
	}

	tmp := new(big.Int).SetBytes(bytes)
	tmp.Mod(tmp, toBigInt(&prime))

	*f = *fromBigInt(tmp)
}

// fromBigInt converts a *big.Int to a field element.
// Returns zero for nil or negative inputs.
func fromBigInt(i *big.Int) *field {
	out := new(field)
	if i == nil || i.Sign() < 0 {
		return out
	}

	tmp := i
	pBig := toBigInt(&prime)
	if i.Cmp(pBig) >= 0 {
		tmp = new(big.Int).Mod(i, pBig)
	}

	bytes := tmp.Bytes()

	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		bytes = padded
	}

	// Convert from big-endian bytes to little-endian limbs
	out.limbs[0] = binary.BigEndian.Uint64(bytes[24:32]) // LSB limb
	out.limbs[1] = binary.BigEndian.Uint64(bytes[16:24])
	out.limbs[2] = binary.BigEndian.Uint64(bytes[8:16])
	out.limbs[3] = binary.BigEndian.Uint64(bytes[0:8]) // MSB limb

	return out
}

// toBigInt converts a field element to *big.Int.
func toBigInt(f *field) *big.Int {
	bytes := make([]byte, 32)
	// Convert little-endian limbs to big-endian bytes
	binary.BigEndian.PutUint64(bytes[24:32], f.limbs[0]) // LSB
	binary.BigEndian.PutUint64(bytes[16:24], f.limbs[1])
	binary.BigEndian.PutUint64(bytes[8:16], f.limbs[2])
	binary.BigEndian.PutUint64(bytes[0:8], f.limbs[3]) // MSB
	return new(big.Int).SetBytes(bytes)
}

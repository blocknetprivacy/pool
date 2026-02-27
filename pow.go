package main

import (
	"encoding/binary"
	"math/bits"

	"golang.org/x/crypto/argon2"
)

// Argon2id PoW parameters — must match the blocknet node exactly.
const (
	powMemoryKB    = 2 * 1024 * 1024 // 2GB in KB
	powIterations  = 1
	powParallelism = 1
	powOutputLen   = 32
)

// PowHash computes the Argon2id hash for proof of work.
// password = nonce (8 bytes LE), salt = headerBase (92 bytes).
func PowHash(headerBase []byte, nonce uint64) [32]byte {
	nonceBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBuf, nonce)

	hash := argon2.IDKey(nonceBuf, headerBase, powIterations, powMemoryKB, powParallelism, powOutputLen)

	var out [32]byte
	copy(out[:], hash)
	return out
}

// CheckTarget returns true if hash <= target (big-endian comparison).
func CheckTarget(hash, target [32]byte) bool {
	for i := 0; i < 32; i++ {
		if hash[i] < target[i] {
			return true
		}
		if hash[i] > target[i] {
			return false
		}
	}
	return true // equal
}

// difficultyToTarget converts difficulty to a 32-byte target.
// Matches the blocknet node implementation exactly:
// start with all 0xFF, then zero out leading bits based on difficulty.
func difficultyToTarget(difficulty uint64) [32]byte {
	var target [32]byte
	for i := range target {
		target[i] = 0xFF
	}

	if difficulty == 0 {
		return target
	}

	// leadingZeros = 63 - leading_zeros(difficulty) = number of bits to zero out
	// This matches Rust: 63 - difficulty.leading_zeros()
	lz := bits.LeadingZeros64(difficulty)
	leadingZeros := uint(63 - lz)

	zeroBytes := leadingZeros / 8
	remainingBits := leadingZeros % 8

	for i := uint(0); i < zeroBytes && i < 32; i++ {
		target[i] = 0x00
	}

	if zeroBytes < 32 {
		target[zeroBytes] = 0xFF >> remainingBits
	}

	return target
}

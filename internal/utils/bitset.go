package utils

// Bitset provides a bit array built on top of a byte slice.
// Each byte in the underlying slice encodes 8 bits.
type Bitset []byte

// NewBitset returns a Bitset that "compress" the bits argument.
func NewBitset(bits []bool) Bitset {
	size := len(bits) / 8
	if 0 != (len(bits) % 8) {
		size += 1
	}
	bitset := make([]byte, size)
	var byteIdx, shift int
	for pos, bit := range bits {
		if bit {
			byteIdx = pos / 8
			shift = 7 - (pos % 8)
			bitset[byteIdx] |= (1 << shift)
		}
	}

	return bitset
}

// SetBit set the bit indexed by pos to 1.
// It errors if pos is not a valid index in the Bitset.
func (self Bitset) SetBit(pos int) error {
	if (pos < 0) || (pos >= 8*len(self)) {
		return newError("Bit index out of range")
	}
	byteIdx := pos / 8
	shift := 7 - (pos % 8)
	self[byteIdx] |= (1 << shift)

	return nil
}

// ClearBit set the bit indexed by pos to 0.
// It errors if pos is not a valid index in the Bitset.
func (self Bitset) ClearBit(pos int) error {
	if (pos < 0) || (pos >= 8*len(self)) {
		return newError("Bit index out of range")
	}
	byteIdx := pos / 8
	shift := 7 - (pos % 8)
	self[byteIdx] &= ^(1 << shift)

	return nil
}

// GetBit returns the bit indexed by pos as a bool.
// It errors if pos is not a valid index
func (self Bitset) GetBit(pos int) (bool, error) {
	if (pos < 0) || (pos >= 8*len(self)) {
		return false, newError("Bit index out of range")
	}
	byteIdx := pos / 8
	shift := 7 - (pos % 8)
	var val bool
	if (self[byteIdx] & (1 << shift)) > 0 {
		val = true
	}

	return val, nil
}

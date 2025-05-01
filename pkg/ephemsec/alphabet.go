package ephemsec

import (
	"strings"
	"unicode"
)

const (
	maxAlphabetSize = 256
	maxOtpBytes     = 64
	B10Alphabet     = Alphabet("0123456789")
	B16Alphabet     = Alphabet("0123456789ABCDEF")
	B32Alphabet     = Alphabet("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
	NullAlphabet    = Alphabet("")
)

// Alphabet defines a mapping in between unicode characters and bytes.
// Alphabet are used to convert OTP to text.
type Alphabet string

// Check determines if Alphabet is valid.
func (self Alphabet) Check() error {
	if self.Size() > maxAlphabetSize {
		return newError("Invalid alphabet, longer than %d characters", maxAlphabetSize)
	}
	alphabet := string(self)
	for pos, r := range alphabet {
		if pos != strings.IndexRune(alphabet, r) {
			return newError("Invalid alphabet, found repetition of character %s", r)
		}
	}
	return nil
}

// Format transforms digits into text. It errors if digits contains values not compatible with
// the Alphabet size.
//
// The group parameter allows controlling the insertion of the separator sep. sep is added
// after group consecutive characters. sep insertion is disabled by setting group to 0.
func (self Alphabet) Format(digits []byte, group int, sep rune) (string, error) {
	alphabet := []rune(self)
	asz := byte(len(alphabet))
	var sb strings.Builder
	for digitcount, digit := range digits {
		if digit >= asz {
			return "", newError("invalid digit index at position %d", digitcount)
		}
		if (group > 0) && (digitcount > 0) && (0 == (digitcount % group)) {
			sb.WriteRune(sep)
		}
		sb.WriteRune(alphabet[digit])
	}
	return sb.String(), nil
}

// Decode returns the digits decoded from otp Alphabet characters. It errors if less than
// size digits were recovered or if otp contains non valid Alphabet characters.
//
// Decoded digits are appended to the dst buffer. Decode allocates storage if dst capacity
// is not sufficient to hold decoded digits.
//
// Decode ignores sep and ' ' characters present in otp string. When Decode encounters a
// a character not present in the Alphabet, it retries decoding it toggling its case.
func (self Alphabet) Decode(otp string, sep rune, size int, dst []byte) ([]byte, error) {
	if len(otp) > maxOtpBytes {
		// this check mitigates DOS attacks where attackers would submit very large otp...
		return nil, newError("otp is too large")
	}

	alphabet := string(self)
	var digitcount, pos int
	for _, char := range otp {
		if digitcount == size {
			break
		}
		switch char {
		case ' ', sep:
			continue
		default:
			pos = strings.IndexRune(alphabet, char)
			if -1 == pos {
				// try toggling the case
				pos = strings.IndexRune(alphabet, toggleCase(char))
				if -1 == pos {
					return nil, newError("otp has invalid character")
				}
			}
			dst = append(dst, byte(pos))
			digitcount += 1
		}
	}

	if digitcount < size {
		return nil, newError("otp is too small")
	}

	return dst, nil
}

func (self Alphabet) Size() int {
	return len([]rune(self))
}

func toggleCase(r rune) rune {
	switch {
	case unicode.IsUpper(r):
		return unicode.ToLower(r)
	case unicode.IsLower(r):
		return unicode.ToUpper(r)
	default:
		return r
	}
}

package ephemsec

import (
	"strings"
)

const (
	maxAlphabetSize = 256
	B10Alphabet     = Alphabet("0123456789")
	B16Alphabet     = Alphabet("0123456789ABCDEF")
	B32Alphabet     = Alphabet("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
)

type Alphabet string

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

func (self Alphabet) Size() int {
	return len([]rune(self))
}

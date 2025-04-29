package ephemsec

import (
	"testing"
)

func TestEncodingAlphabetCheck(t *testing.T) {
	alphabet := Alphabet("abab")
	err := alphabet.Check()
	if nil == err {
		t.Error("Failed, abab alphabet reported valid")
	}

	alphabet = Alphabet("0123456789")
	err = alphabet.Check()
	if nil != err {
		t.Errorf("Failed checking 0123456789, got error %v", err)
	}
	if 10 != alphabet.Size() {
		t.Errorf("Failed checking 0123456789")
	}
}

func TestEncodingAlphabet(t *testing.T) {
	alphabetSpecs := []struct {
		name     string
		alphabet Alphabet
		size     int
	}{
		{name: "B10", alphabet: B10Alphabet, size: 10},
		{name: "B16", alphabet: B16Alphabet, size: 16},
		{name: "B32", alphabet: B32Alphabet, size: 32},
	}
	for _, spec := range alphabetSpecs {
		t.Run(spec.name, func(t *testing.T) {
			alfa := spec.alphabet
			err := alfa.Check()
			if nil != err {
				t.Fatalf("Failed checking %s alphabet, got error %v", spec.name, err)
			}
			if alfa.Size() != spec.size {
				t.Fatalf("Failed checking %s alphabet, size %d != %d", spec.name, alfa.Size(), spec.size)
			}
		})
	}
}

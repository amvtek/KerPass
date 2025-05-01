package ephemsec

import (
	"fmt"
	"reflect"
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

func TestAlphabetFormat(t *testing.T) {
	testcases := []struct {
		alphabet Alphabet
		digits   []byte
		expect   string
		group    int
		sep      rune
		fail     bool
	}{
		{
			alphabet: B10Alphabet,
			digits:   []byte{0, 1, 2, 3, 4, 5},
			expect:   "012 345",
			group:    3,
			sep:      ' ',
		},
		{
			alphabet: B16Alphabet,
			digits:   []byte{0, 1, 14, 15, 2, 3},
			expect:   "01-EF-23",
			group:    2,
			sep:      '-',
		},
		{
			alphabet: B32Alphabet,
			digits:   []byte{0, 1, 14, 15, 2, 3, 30, 31},
			expect:   "01EF~23YZ",
			group:    4,
			sep:      '~',
		},
		{
			alphabet: B32Alphabet,
			digits:   []byte{0, 1, 14, 15, 2, 3, 30, 31},
			expect:   "01EF23YZ",
			group:    0,
			sep:      '~',
		},
		{
			alphabet: B10Alphabet,
			digits:   []byte{10, 11, 12},
			fail:     true,
		},
	}

	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			otp, err := tc.alphabet.Format(tc.digits, tc.group, tc.sep)
			if tc.fail {
				if nil == err {
					t.Fatalf("Should have failed but Format returned no error")
				}
				return
			}
			if otp != tc.expect {
				t.Fatalf("Failed otp control got:\n%s\n!=\n%s", otp, tc.expect)
			}
		})
	}
}

func TestAlphabetDecode(t *testing.T) {
	testcases := []struct {
		alphabet Alphabet
		otp      string
		sep      rune
		size     int
		expect   []byte
		fail     bool
	}{
		{
			alphabet: B32Alphabet,
			otp:      " 1234-WXYZ ",
			sep:      '-',
			size:     8,
			expect:   []byte{1, 2, 3, 4, 28, 29, 30, 31},
		},
		{
			alphabet: B32Alphabet,
			otp:      " 1234 WXYZ ",
			sep:      ' ',
			size:     8,
			expect:   []byte{1, 2, 3, 4, 28, 29, 30, 31},
		},
		{
			alphabet: B32Alphabet,
			otp:      " 1234 WXYZ ",
			sep:      rune(0),
			size:     8,
			expect:   []byte{1, 2, 3, 4, 28, 29, 30, 31},
			fail:     false, // succeed as ' ' is always a valid separator
		},
		{
			alphabet: B32Alphabet,
			otp:      " 1234-WXYZ$$$$$",
			sep:      '-',
			size:     8,
			expect:   []byte{1, 2, 3, 4, 28, 29, 30, 31},
			fail:     false, // succeed as '$' appears after otp characters
		},
		{
			alphabet: B32Alphabet,
			otp:      " 1234-WXYZ ",
			sep:      '~',
			size:     8,
			fail:     true, // fail as '-' is not in alphabet
		},
		{
			alphabet: B16Alphabet,
			otp:      " 1234-WXYZ ",
			sep:      '-',
			size:     8,
			fail:     true, // fail as 'W' is not in alphabet
		},
		{
			alphabet: B32Alphabet,
			otp:      " 1234-WXYZ ",
			sep:      '-',
			size:     10,
			fail:     true, // fail as otp is too small
		},
		{
			alphabet: Alphabet("aBcD"),
			otp: "Ab:Bd",
			sep: ':',
			size: 4,
			expect: []byte{0, 1, 1, 3},
			fail: false, // succeed as Decode toggle the case of non matching characters
		},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			digits, err := tc.alphabet.Decode(tc.otp, tc.sep, tc.size, nil)
			if tc.fail {
				if nil == err {
					t.Fatalf("Should have failed but Decode returned no error")
				}
				return
			}
			if !reflect.DeepEqual(digits, tc.expect) {
				t.Fatalf("Failed digits control got:\n%+v\n!=\n%+v", digits, tc.expect)
			}
		})
	}
}

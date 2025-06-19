package utils

import (
	"fmt"
	"reflect"
	"testing"
)

func TestBitsetBoolArray(t *testing.T) {
	// validates makeBoolArray function...
	testcases := []struct {
		sbs string
		bbs []bool
	}{
		{sbs: "101", bbs: []bool{true, false, true}},
		{sbs: "1010__11_", bbs: []bool{true, false, true, false, true, true}},
		{sbs: "11100", bbs: []bool{true, true, true, false, false}},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			bbs := makeBoolArray(tc.sbs)
			if !reflect.DeepEqual(bbs, tc.bbs) {
				t.Fatalf("Failed bbs control\n%v\n!=\n%v", bbs, tc.bbs)
			}
		})
	}
}

func TestBitset(t *testing.T) {
	testcases := []struct {
		sbs  string
		size int
	}{
		{sbs: "101", size: 3},
		{sbs: "0000_1", size: 5},
		{sbs: "0000_1111_1010_0011", size: 16},
		{sbs: "1011_0011_1111_0000_111", size: 19},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			bbs := makeBoolArray(tc.sbs)
			if len(bbs) != tc.size {
				t.Fatalf("[1] failed size control, %d != %d", len(bbs), tc.size)
			}

			bitset := NewBitset(bbs)

			var bit bool
			var err error
			for pos, refbit := range bbs {

				bit, err = bitset.GetBit(pos)
				if nil != err {
					t.Fatalf("[2] failed GetBit(%d), got error %v", pos, err)
				}
				if bit != refbit {
					t.Fatalf("[3] failed GetBit(%d) control, %v != %v", pos, bit, refbit)
				}

				err = bitset.SetBit(pos)
				if nil != err {
					t.Fatalf("[4] failed SetBit(%d), got error %v", pos, err)
				}
				bit, err = bitset.GetBit(pos)
				if nil != err {
					t.Fatalf("[5] failed GetBit(%d), got error %v", pos, err)
				}
				if bit != true {
					t.Fatalf("[6] failed GetBit(%d) control, %v != true", pos, bit)
				}

				err = bitset.ClearBit(pos)
				if nil != err {
					t.Fatalf("[7] failed ClearBit(%d), got error %v", pos, err)
				}
				bit, err = bitset.GetBit(pos)
				if nil != err {
					t.Fatalf("[8] failed GetBit(%d), got error %v", pos, err)
				}
				if bit != false {
					t.Fatalf("[9] failed GetBit(%d) control, %v != false", pos, bit)
				}

			}

		})
	}
}

func makeBoolArray(bitset string) []bool {
	var rv []bool
	for _, bit := range bitset {
		switch bit {
		case '0':
			rv = append(rv, false)
		case '1':
			rv = append(rv, true)
		default:
			continue
		}
	}

	return rv
}

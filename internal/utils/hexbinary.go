package utils

import (
	"encoding/hex"
)

type HexBinary []byte

func (self *HexBinary) UnmarshalText(text []byte) error {
	var dst []byte
	hxsz := hex.DecodedLen(len(text))
	if cap([]byte(*self)) >= hxsz {
		dst = []byte(*self)[:0]
	} else {
		dst = make([]byte, 0, hxsz)
	}

	_, err := hex.AppendDecode(dst, text)
	if nil != err {
		return err
	}

	*self = HexBinary(dst)
	return nil
}

func (self HexBinary) MarshalText() ([]byte, error) {
	var dst []byte
	dst = hex.AppendEncode(dst, []byte(self))
	return dst, nil
}

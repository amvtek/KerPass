package enroll

import (
	"bytes"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	markRealm = byte('R')
	markPerso = byte('P')
	persoPsk  = "card-psk"
)

func derivePSK(realmId, cardId, handshakeHash []byte) ([]byte, error) {

	// derive domain separation salt
	if len(realmId) > 255 || len(persoPsk) > 255 {
		return nil, newError("Invalid realmId or persoPsk, length exceeds 255")
	}
	var buf bytes.Buffer
	buf.Grow(2 + 2 + len(realmId) + len(persoPsk))
	buf.WriteByte(markRealm)
	buf.WriteByte(byte(len(realmId)))
	buf.Write(realmId)
	buf.WriteByte(markPerso)
	buf.WriteByte(byte(len(persoPsk)))
	buf.WriteString(persoPsk)
	salt := buf.Bytes()

	ikm := handshakeHash

	info := cardId

	psk := make([]byte, 32)
	rdr := hkdf.New(sha512.New, ikm, salt, info)
	_, err := io.ReadFull(rdr, psk)
	if nil != err {
		return nil, wrapError(err, "failed psk generation")
	}

	return psk, nil
}

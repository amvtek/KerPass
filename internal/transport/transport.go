package transport

import (
	"encoding/binary"
	"io"

	"code.kerpass.org/golang/pkg/noise"
)

// Transport read/write messages after converting them to bytes
type Transport struct {
	R io.Reader                  // source from which messages are read.
	W io.Writer                  // destination to which messages are written.
	S Serializer                 // Convert messages to bytes and bytes to messages.
	C *noise.TransportCipherPair // Encrypt/Decrypt messages bytes.
}

// T aliases Transport
type T = Transport

// WriteMessage converts msg to bytes and writes msg bytes to inner io.Writer.
//
// If the Transport has an inner Cipher, msg bytes are encrypted prior to be written.
func (self Transport) WriteMessage(msg any) error {
	var srzmsg []byte
	var err error

	switch v := msg.(type) {
	case RawMsg:
		srzmsg = []byte(v)
	default:
		srzmsg, err = self.S.Marshal(msg)
		if nil != err {
			return wrapError(err, "failed marshalling msg")
		}
	}

	if nil != self.C {
		// we need to apply encryption
		enc := self.C.Encryptor()
		srzmsg, err = enc.EncryptWithAd(nil, srzmsg)
		if nil != err {
			return wrapError(err, "failed encrypting msg")
		}
	}

	if len(srzmsg) > 0xFFFF {
		return newError("serialized message larger than %d", 0xFFFF)
	}

	// prefix msg with uint16 length
	pmsg := make([]byte, 2+len(srzmsg))
	binary.BigEndian.PutUint16(pmsg, uint16(len(srzmsg)))
	copy(pmsg[2:], srzmsg)

	_, err = self.W.Write(pmsg)

	return wrapError(err, "failed writing msg") // nil if err is nil ...
}

// ReadMessage reads msg bytes from inner io.Reader and deserializes them to msg.
//
// If the Transport has an inner Cipher, msg bytes are decrypted prior to be deserialized.
func (self Transport) ReadMessage(msg any) error {
	// read size
	psb := make([]byte, 2)
	_, err := io.ReadFull(self.R, psb)
	if nil != err {
		return wrapError(err, "failed reading message size")
	}
	psz := binary.BigEndian.Uint16(psb)

	// read srzmsg
	srzmsg := make([]byte, int(psz))
	_, err = io.ReadFull(self.R, srzmsg)
	if nil != err {
		return wrapError(err, "failed reading message bytes")
	}

	// optionally decrypt srzmsg
	if nil != self.C {
		dec := self.C.Decryptor()
		srzmsg, err = dec.DecryptWithAd(nil, srzmsg)
		if nil != err {
			return wrapError(err, "failed decrypting message")
		}
	}

	// unmarshal srzmsg
	switch v := msg.(type) {
	case *RawMsg:
		*v = RawMsg(srzmsg)
	default:
		err = self.S.Unmarshal(srzmsg, msg)
	}

	return wrapError(err, "failed unmarshaling message") // nil if err is nil

}

// RawMsg is a "marker" type used to disable serialization
type RawMsg []byte

// Serializer provides methods to Marshal/Unmarshal messages.
type Serializer interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
}

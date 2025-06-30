package transport

import (
	"encoding/binary"
	"io"

	"code.kerpass.org/golang/pkg/noise"
)

type Transport interface {
	ReadBytes() ([]byte, error)
	WriteBytes(data []byte) error
}

// T aliases Transport
type T = Transport

// MessageTransport read/write messages to inner Transport after converting them to bytes
type MessageTransport struct {
	Transport
	S Serializer                 // Convert messages to bytes and bytes to messages.
	C *noise.TransportCipherPair // Encrypt/Decrypt messages bytes.
}

// WriteMessage converts msg to bytes and writes msg bytes to inner Transport.
//
// If the MessageTransport has an inner Cipher, msg bytes are encrypted prior to be written.
func (self MessageTransport) WriteMessage(msg any) error {
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

	err = self.WriteBytes(srzmsg)

	return wrapError(err, "failed writing msg") // nil if err is nil ...
}

// ReadMessage reads msg bytes from inner Transport and deserializes them to msg.
//
// If the MessageTransport has an inner Cipher, msg bytes are decrypted prior to be deserialized.
func (self MessageTransport) ReadMessage(msg any) error {

	srzmsg, err := self.ReadBytes()
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

type RWTransport struct {
	R io.Reader // source from which messages are read.
	W io.Writer // destination to which messages are written.
}

func (self RWTransport) ReadBytes() ([]byte, error) {
	// read size
	psb := make([]byte, 2)
	_, err := io.ReadFull(self.R, psb)
	if nil != err {
		return nil, wrapError(err, "failed reading data size")
	}
	psz := binary.BigEndian.Uint16(psb)

	// read data
	data := make([]byte, int(psz))
	_, err = io.ReadFull(self.R, data)
	if nil != err {
		return nil, wrapError(err, "failed reading data")
	}

	return data, nil
}

func (self RWTransport) WriteBytes(data []byte) error {
	if len(data) > 0xFFFF {
		return newError("data larger than %d", 0xFFFF)
	}

	// prefix data with uint16 length
	pdata := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(pdata, uint16(len(data)))
	copy(pdata[2:], data)

	_, err := self.W.Write(pdata)

	return wrapError(err, "failed writing data") // nil if err is nil
}

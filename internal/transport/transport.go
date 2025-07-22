package transport

import (
	"encoding/binary"
	"io"
)

// Transport is an interface that represented a "framed" transport.
// It defines methods to read/write messages that are byte slices.
type Transport interface {
	ReadBytes() ([]byte, error)
	WriteBytes(data []byte) error
	Close() error
}

// T aliases Transport
type T = Transport

// RWTransport is a Transport that reads from io.Reader and writes to io.Writer.
// It uses a 2 bytes length prefix to properly delimitate messages.
type RWTransport struct {
	R io.Reader // source from which messages are read.
	W io.Writer // destination to which messages are written.
	C io.Closer // ignored if nil
}

// ReadBytes first reads message size (2 bytes prefix) and then reads and returns
// next size bytes as message.
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

// WriteBytes first write data size (2 bytes prefix) and then write data.
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

func (self RWTransport) Close() error {
	if nil != self.C {
		return self.C.Close()
	}

	return nil
}

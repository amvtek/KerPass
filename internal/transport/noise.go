package transport

import (
	"bytes"

	"code.kerpass.org/golang/pkg/noise"
)

// HandshakeTransport connect a Transport with an ongoing noise protocol Handshake.
// It Reads & Writes noise protocol messages payloads.
type HandshakeTransport struct {
	*noise.HandshakeState
	Transport
}

func NewHandshakeTransport(transport Transport) HandshakeTransport {
	return HandshakeTransport{
		HandshakeState: &noise.HandshakeState{},
		Transport:      transport,
	}
}

// ReadBytes reads data from the underlying Transport and pass those data to noise HandshakeState.
// It returns the payload extracted from the data by the noise Handshake.
func (self HandshakeTransport) ReadBytes() ([]byte, error) {
	msg, err := self.Transport.ReadBytes()
	if nil != err {
		return nil, wrapError(err, "failed Transport ReadBytes")
	}

	// update HandshakeState
	var buf bytes.Buffer
	_, err = self.ReadMessage(msg, &buf)
	if nil != err {
		return nil, wrapError(err, "failed noise Handshake ReadMessage")
	}

	return buf.Bytes(), nil
}

// WriteBytes pass data to noise Handshake WriteMessage and forwards the generated message
// to the underlying transport.
func (self HandshakeTransport) WriteBytes(data []byte) error {
	var buf bytes.Buffer
	_, err := self.WriteMessage(data, &buf)
	if nil != err {
		return wrapError(err, "failed noise Handshake WriteMessage")
	}

	return wrapError(
		self.Transport.WriteBytes(buf.Bytes()),
		"failed Transport WriteBytes",
	)
}

package transport

import (
	"sync"
)

// LimitTransport is a Transport that fails after a certain number of messages have been processed.
//
// LimitTransport is provided to simplify protocol testing.
type LimitTransport struct {
	Transport
	mut   sync.Mutex
	rsema int
	wsema int
}

// NewLimitTransport returns a new MessageTransport that wraps mt.
func NewLimitTransport(t Transport) *LimitTransport {

	return &LimitTransport{Transport: t}
}

// SetReadLimit set the maximum number of messages that can be read from the LimitTransport.
func (self *LimitTransport) SetReadLimit(limit int) {
	self.mut.Lock()
	defer self.mut.Unlock()

	self.rsema = -limit
}

// SetWriteLimit set the maximum number of messages that can be written to the LimitTransport.
func (self *LimitTransport) SetWriteLimit(limit int) {
	self.mut.Lock()
	defer self.mut.Unlock()

	self.wsema = -limit
}

// ReadBytes errors if SetReadLimit has been exceeded.
// Otherwise data is read from the underlaying Transport.
func (self *LimitTransport) ReadBytes() ([]byte, error) {
	self.mut.Lock()
	defer self.mut.Unlock()

	self.rsema += 1
	if 0 == self.rsema {
		self.rsema -= 1 // fail again at next call
		return nil, wrapError(ReadLimitError, "test only")
	}

	return self.Transport.ReadBytes()
}

// WriteBytes errors if SetWriteLimit has been exceeded.
// Otherwise data is written to the underlaying Transport.
func (self *LimitTransport) WriteBytes(data []byte) error {
	self.mut.Lock()
	defer self.mut.Unlock()

	self.wsema += 1
	if 0 == self.wsema {
		self.wsema -= 1 // fail again at next call
		return wrapError(WriteLimitError, "test only")
	}

	return self.Transport.WriteBytes(data)
}

var _ Transport = &LimitTransport{}

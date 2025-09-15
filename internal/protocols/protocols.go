package protocols

import (
	"errors"

	"code.kerpass.org/golang/internal/transport"
)

// StateFunc changes state S using incoming []byte message.
// It returns next StateFunc and a message to be forwarded to connected peer.
// To report protocol completion StateFunc returns an error wrapping protocols.OK.
type StateFunc[S any] func(S, []byte) (StateFunc[S], []byte, error)

// Fsm exposes protocol state S.
type Fsm[S any] interface {
	State() (S, StateFunc[S])
	Initiator() bool
	SetState(sf StateFunc[S])
}

// Run reads & writes messages from/to Transport and executes protocol until completion.
func Run[S any](fsm Fsm[S], tr transport.Transport) error {
	s, sf := fsm.State()
	defer func() { fsm.SetState(sf) }()

	var msg []byte
	var errIO, errProto error
	if !fsm.Initiator() {
		msg, errIO = tr.ReadBytes()
		if nil != errIO {
			return wrapError(errIO, "Failed reading initial message")
		}
	}

	for {
		sf, msg, errProto = sf(s, msg)
		if nil != msg {
			errIO = tr.WriteBytes(msg)
			if nil != errIO {
				return wrapError(errIO, "Failed writing message")
			}
		}

		if nil == sf {
			return wrapError(errProto, "Failed state execution")
		}

		if nil == errProto {
			msg, errIO = tr.ReadBytes()
			if nil != errIO {
				return wrapError(errIO, "Failed reading message")
			}
		} else {
			if errors.Is(errProto, OK) {
				return nil
			} else {
				return wrapError(errProto, "Failed state execution")
			}
		}
	}
}

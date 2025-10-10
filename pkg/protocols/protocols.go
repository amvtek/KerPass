package protocols

import (
	"context"
	"errors"

	"code.kerpass.org/golang/internal/transport"
)

// StateFunc changes state S using incoming []byte message.
// It returns next StateFunc and a message to be forwarded to connected peer.
// To report protocol completion StateFunc returns an error wrapping protocols.OK.
type StateFunc[S any] func(context.Context, S, []byte) (StateFunc[S], []byte, error)

// ExitFunc is called at protocol completion using protocol run error status.
type ExitFunc[S any] func(S, error) error

// Fsm exposes protocol state S.
type Fsm[S any] interface {
	State() (S, StateFunc[S])
	SetState(sf StateFunc[S])
	ExitHandler() ExitFunc[S]
	SetExitHandler(ef ExitFunc[S])
	Initiator() bool
}

// Run reads & writes messages from/to Transport and executes protocol until completion.
func Run[S any](ctx context.Context, fsm Fsm[S], tr transport.Transport) error {
	var err error
	s, sf := fsm.State()
	defer func() {
		fsm.SetState(sf)
		exh := fsm.ExitHandler()
		if nil != exh {
			state, _ := fsm.State()
			exh(state, err)
		}
	}()

	var msg []byte
	var errIO, errProto error
	if !fsm.Initiator() {
		msg, errIO = tr.ReadBytes()
		if nil != errIO {
			err = wrapError(errIO, "Failed reading initial message")
			return err
		}
	}

	for {
		sf, msg, errProto = sf(ctx, s, msg)
		if nil != msg {
			errIO = tr.WriteBytes(msg)
			if nil != errIO {
				err = wrapError(errIO, "Failed writing message")
				return err
			}
		}

		if nil == errProto {
			msg, errIO = tr.ReadBytes()
			if nil != errIO {
				err = wrapError(errIO, "Failed reading message")
				return err
			}
		} else {
			if errors.Is(errProto, OK) {
				err = nil
				return err
			} else {
				err = wrapError(errProto, "Failed state execution")
				return err
			}
		}
	}
}

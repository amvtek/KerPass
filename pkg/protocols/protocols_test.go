package protocols

import (
	"bytes"
	"context"
	"io"
	"testing"

	"code.kerpass.org/golang/internal/observability"
	"code.kerpass.org/golang/internal/transport"
)

func TestRunFsmInitiator(t *testing.T) {
	fsm := &dummyFsm{sf: dummyInit, initiator: true}
	tr := mockTransport{Msg: []byte("stuff...")}

	err := Run(context.Background(), fsm, tr)
	if nil != err {
		t.Fatalf("failed fsm Run, got error %v", err)
	}
}

func TestRunFsmResponder(t *testing.T) {
	fsm := &dummyFsm{sf: dummyInit, initiator: false}
	tr := mockTransport{Msg: []byte("stuff...")}

	err := Run(context.Background(), fsm, tr)
	if nil != err {
		t.Fatalf("failed fsm Run, got error %v", err)
	}
}

func TestRunFsmFailProto01(t *testing.T) {
	fsm := &dummyFsm{sf: dummyInit, initiator: true}
	tr := mockTransport{Msg: failmsg}

	err := Run(context.Background(), fsm, tr)
	if nil == err {
		t.Fatalf("failed fsm Run, no error reported")
	}
}

func TestRunFsmFailProto02(t *testing.T) {
	fsm := &dummyFsm{sf: dummyInit, initiator: false}
	tr := mockTransport{Msg: failmsg}

	err := Run(context.Background(), fsm, tr)
	if nil == err {
		t.Fatalf("failed fsm Run, no error reported")
	}
}

func TestRunFsmFailIO01(t *testing.T) {
	fsm := &dummyFsm{sf: dummyInit, initiator: true}
	tr := mockTransport{Msg: []byte("stuff"), Err: io.EOF}

	err := Run(context.Background(), fsm, tr)
	if nil == err {
		t.Fatalf("failed fsm Run, no error reported")
	}
}

func TestRunFsmFailIO02(t *testing.T) {
	fsm := &dummyFsm{sf: dummyInit, initiator: true}
	tr := mockTransport{Msg: []byte("stuff"), Err: io.EOF}

	err := Run(context.Background(), fsm, tr)
	if nil == err {
		t.Fatalf("failed fsm Run, no error reported")
	}
}

// Fsm implementation

type dummy struct{}

type dummyFsm struct {
	sf        StateFunc[dummy]
	initiator bool
}

func (self *dummyFsm) State() (dummy, StateFunc[dummy]) {
	return dummy{}, self.sf
}

func (self *dummyFsm) SetState(sf StateFunc[dummy]) {
	self.sf = sf
}

func (self *dummyFsm) ExitHandler() ExitFunc[dummy] {
	return nil
}

func (self *dummyFsm) SetExitHandler(_ ExitFunc[dummy]) {
}

func (self *dummyFsm) Initiator() bool {
	return self.initiator
}

var _ Fsm[dummy] = &dummyFsm{}

// State functions

var failmsg = []byte("FAIL")

func dummyInit(ctx context.Context, _ dummy, msg []byte) (sf StateFunc[dummy], rmsg []byte, err error) {
	log := observability.GetObservability(ctx).Log().With("state", "dummyInit")
	log.Info("entering state")
	sf = dummyInit
	if bytes.Equal(msg, failmsg) {
		sf = dummyFail
		err = newError("received the FAIL msg")
		log.Info("transitioning to dummyFail state")
		return sf, rmsg, err
	}
	if len(msg) > 0 {
		sf = dummyOk
		err = wrapError(OK, "this is It")
		log.Info("returning protocols.OK")
	}
	rmsg = []byte("NEXT")

	return sf, rmsg, err

}

func dummyFail(ctx context.Context, _ dummy, _ []byte) (sf StateFunc[dummy], rmsg []byte, err error) {
	log := observability.GetObservability(ctx).Log().With("state", "dummyFail")
	log.Info("entering state")
	sf = dummyFail
	err = newError("failed previously...")

	return sf, rmsg, err
}

func dummyOk(ctx context.Context, _ dummy, _ []byte) (sf StateFunc[dummy], rmsg []byte, err error) {
	log := observability.GetObservability(ctx).Log().With("state", "dummyOk")
	log.Info("entering state")
	sf = dummyOk
	// panic if called in Run...
	panic("I don't expect to be called...")
}

// Transport implementation

type mockTransport struct {
	Msg []byte
	Err error
}

func (self mockTransport) ReadBytes() ([]byte, error) {
	return self.Msg, self.Err
}

func (self mockTransport) WriteBytes(_ []byte) error {
	return self.Err
}

func (self mockTransport) Close() error {
	return nil
}

var _ transport.Transport = mockTransport{}

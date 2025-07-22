package protocols

import (
	"bytes"
	"log"
	"net"
	"testing"
	"time"

	"code.kerpass.org/golang/internal/transport"
)

func TestRunEchoInitiator(t *testing.T) {
	p := &EchoProtocol{maxRound: 4, initiator: true, preamble: "foobarbaz"}
	transport := echoTransport()
	var hc CommandHandler // nil handler

	result, err := Run(p, transport, hc)
	if nil != err {
		t.Fatalf("failed running Echo protocol, got error %v", err)
	}
	iresult, ok := result.(int)
	if !ok {
		t.Fatal("failed casting protocol result to int")
	}
	if 4 != iresult {
		t.Errorf("failed result control, %d != 4", iresult)
	}

	if 4 != p.state {
		t.Errorf("failed state control, %d != 4", p.state)
	}

}

func TestRunEchoResponder(t *testing.T) {
	p := &EchoProtocol{maxRound: 4, initiator: false}
	transport := echoTransport()
	var hc CommandHandler // nil handler

	// add an initial message in transport
	err := transport.WriteBytes([]byte("echo-token"))
	if nil != err {
		t.Fatal("failed writing echo-token in t")
	}

	result, err := Run(p, transport, hc)
	if nil != err {
		t.Fatalf("failed running Echo protocol, got error %v", err)
	}
	iresult, ok := result.(int)
	if !ok {
		t.Fatal("failed casting protocol result to int")
	}
	if 4 != iresult {
		t.Errorf("failed result control, %d != 4", iresult)
	}

	if 4 != p.state {
		t.Errorf("failed state control, %d != 4", p.state)
	}

}

// suitable for EchoProtocol tests only.
func echoTransport() transport.RWTransport {
	var buf bytes.Buffer
	return transport.RWTransport{R: &buf, W: &buf}
}

// a simple EchoProtocol that can be updated maxRound times.
type EchoProtocol struct {
	state     int
	maxRound  int
	initiator bool
	preamble  string
}

func (self *EchoProtocol) Update(evt Event) (cmd Command, err error) {
	log.Printf(`[%d] Update called with event "%s"`, self.state, evt.Tag)
	cmd.Tag = CmdMessage

	switch {
	case 0 == self.state:
		if self.initiator {
			log.Printf(`[%d] sending preamble "%s"`, self.state, self.preamble)
			cmd.Msg = []byte(self.preamble)
		} else {
			cmd.Tag = CmdNoop
		}
		self.state += 1
	case (self.state > 0) && (self.state < self.maxRound):
		log.Printf(`[%d] received "%s"`, self.state, string(evt.Msg))
		cmd.Msg = evt.Msg
		self.state += 1
	case self.maxRound == self.state:
		cmd.Tag = CmdReturn
		cmd.Data = any(self.state)
	default:
		err = newError("invalid EchoProtocol state %d", self.state)
	}

	return cmd, err
}

func TestRunSimpleClientServer(t *testing.T) {
	type rv struct {
		result any
		err    error
	}

	deadline := time.Now().Add(750 * time.Millisecond)
	c, s := net.Pipe()
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)

	rtcli := make(chan rv, 1)
	cli := &SimpleClient{}                        // proto
	transcli := transport.RWTransport{R: c, W: c} // transport
	go func(result chan<- rv) {
		r, e := Run(cli, transcli, nil)
		rt := rv{result: r, err: e}
		result <- rt
	}(rtcli)

	rtsrv := make(chan rv, 1)
	srv := &SimpleServer{}                        // proto
	transsrv := transport.RWTransport{R: s, W: s} // transport
	msgdb := MsgDB{msgs: []string{"alfa", "bravo", "charlie"}}
	go func(result chan<- rv) {
		r, e := Run(srv, transsrv, msgdb)
		rt := rv{result: r, err: e}
		result <- rt
	}(rtsrv)

	cr := <-rtcli
	if nil != cr.err {
		t.Errorf("Failed client protocol, got error %v", cr.err)
	}

	sr := <-rtsrv
	if nil != sr.err {
		t.Errorf("Failed server protocol, got error %v", sr.err)
	}

}

// SimpleClient is a Protocol that receives a Sequence of Server provided messages and log them.
type SimpleClient struct {
	state    int
	maxRound int
}

func (self *SimpleClient) Update(evt Event) (Command, error) {
	msg := evt.Msg
	cmd := Command{Tag: CmdMessage}
	var err error

	log.Printf("Client[%d]: Update called with event %s", self.state, evt.Tag)

	switch {
	case 0 == self.state:
		// send "hello" to the server...
		cmd.Msg = []byte("hello")
		log.Printf("Client[%d]: prepare forwarding hello", self.state)
		self.state += 1

	case 1 == self.state:
		// receives sequence size from the server
		if len(msg) == 1 {
			size := int(msg[0])
			log.Printf("Client[%d]: received sequence size %d", self.state, size)
			self.maxRound = self.state + 1 + size
			cmd.Msg = []byte("next")
			log.Printf(`Client[%d]: prepare forwarding "next"`, self.state)
			self.state += 1
		} else {
			err = newError("invalid sequence size msg %X", msg)
		}

	case self.state > 1 && self.state < self.maxRound:
		log.Printf("Client[%d]: new sequence message %s", self.state, string(msg))
		cmd.Msg = []byte("next")
		self.state += 1

	case self.maxRound == self.state:
		if !bytes.Equal(msg, []byte("finished")) {
			err = newError("invalid termination message %s", string(msg))
		} else {
			cmd.Tag = CmdReturn
			cmd.Data = any(self.maxRound - 2)
			self.state += 1
		}

	default:
		err = newError("invalid state %d", self.state)
	}

	return cmd, err
}

type SimpleServer struct {
	state    int
	maxRound int
}

func (self *SimpleServer) Update(evt Event) (Command, error) {
	msg := evt.Msg
	cmd := Command{Tag: CmdMessage}
	var err error
	smsg := string(msg)

	log.Printf("Server[%d]: Update called with event %s", self.state, evt.Tag)

	switch {
	case 0 == self.state:

		if evt.Tag != EvtInit {
			err = newError("Invalid initialization event")
			break
		}

		// issue CmdNoop to wait on client hello
		cmd.Tag = CmdNoop
		self.state += 1

	case 1 == self.state:

		if smsg != "hello" {
			err = newError("Invalid client message %s != hello", smsg)
			break
		}

		log.Printf("Server[%d]: requesting MsgDB.Size", self.state)

		// request size of MsgDB ...
		cmd.Tag = "MsgDB.Size"
		cmd.Data = any("size")
		self.state += 1

	case 2 == self.state:

		// process reply to MsgDB.Size
		if evt.Tag != "MsgDB.Size" {
			err = newError("Invalid MsgDB.Size reply")
			break
		}
		size := int(msg[0])
		self.maxRound = self.state + 1 + 2*size

		// forwards size to Client
		log.Printf("Server[%d]: forwarding MsgDB.Size = %d", self.state, size)
		cmd.Msg = msg
		self.state += 1

	case (3 <= self.state) && (self.state < self.maxRound) && (1 == (self.state % 2)):

		// msg should be a "next"
		if smsg != "next" {
			err = newError("Invalid msg %X != next", msg)
			break
		}

		// request next MsgDB msg
		msgidx := (self.state - 2) / 2 // integer division...
		log.Printf("Server[%d]: requesting MsgDB.Get(%d)", self.state, msgidx)
		cmd.Tag = "MsgDB.Get"
		cmd.Data = any(msgidx) // index of to be retrieved MsgDB msg...
		self.state += 1

	case (3 <= self.state) && (self.state < self.maxRound) && (0 == (self.state % 2)):

		// msg is retrieved MsgDB msg
		cmd.Msg = msg
		log.Printf("Server[%d]: forwarding MsgDB msg %s", self.state, smsg)
		self.state += 1

	case self.maxRound == self.state:

		cmd.Tag = CmdReturn
		log.Printf("Server[%d]: forwarding finished msg", self.state)
		cmd.Msg = []byte("finished")
		self.state += 1

	default:

		err = newError("invalid state %d", self.state)
	}

	return cmd, err
}

// MsgDB holds a collection of messages and implements a CommandHandler that allows
// querying such collection...
type MsgDB struct {
	msgs []string
}

func (self MsgDB) Handle(cmd Command) (evt Event, err error) {
	switch cmd.Tag {
	case "MsgDB.Size":
		evt.Tag = cmd.Tag
		evt.Msg = []byte{byte(len(self.msgs))}
	case "MsgDB.Get":
		index, ok := cmd.Data.(int)
		if !ok {
			err = newError("invalid MsgDB.Get Command, can not load index")
			break
		}
		if index < 0 || index >= len(self.msgs) {
			err = newError("invalid MsgDB.Get Command, index not in range")
			break
		}
		evt.Tag = cmd.Tag
		evt.Msg = []byte(self.msgs[index])
	default:
		err = newError("unsupported Command %s", cmd.Tag)
	}

	return evt, err
}

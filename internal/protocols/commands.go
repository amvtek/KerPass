package protocols

const (
	CmdMsg    = "WriteMessage" // used to write a Message to transport.
	CmdReturn = "Return"       // used to return Protocol Result.
	CmdNoop   = "Noop"         // used to pause a Protocol.
	CmdWait   = CmdNoop        // used to pause a protocol for waiting next transport Message.
)

// Command describes an IO operation or a long running computation awaited by a running Protocol.
type Command struct {
	Tag  string `json:"tag" cbor:"1,keyasint"`
	Msg  []byte `json:"msg,omitempty" cbor:"2,keyasint,omitempty"`
	Data any    `json:"data,omitempty" cbor:"3,keyasint,omitempty"`
}

// CommandHandler exports a single Handle method.
//
// Handle executes a ProtocolFSM Command and returns an Event that needs to be passed
// to the ProtocolFSM Update method.
type CommandHandler interface {
	Handle(cmd Command) (evt Event, err error)
}

// CommandHandlerFunc is an adapter that allows using ordinary functions as CommandHandler.
type CommandHandlerFunc func(cmd Command) (evt Event, err error)

func (self CommandHandlerFunc) Handle(cmd Command) (evt Event, err error) {
	return self(cmd)
}

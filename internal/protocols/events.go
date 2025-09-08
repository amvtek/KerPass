package protocols

const (
	EvtInit         = "Init"
	EvtMsg          = "ReadMessage"
	EvtMsgDelivered = "MsgDelivered"
	EvtMsgFailed    = "MsgNotDelivered"
	EvtAbort        = "Abort"
	EvtTimeout      = "Timeout"
)

// Event contains "incoming" data processed by a ProtocolFSM.
type Event struct {
	Tag  string `json:"tag" cbor:"1,keyasint"`
	Msg  []byte `json:"msg,omitempty" cbor:"2,keyasint,omitempty"`
	Data any    `json:"data,omitempty" cbor:"3,keyasint,omitempty"`
}

// Init returns an EvtInit Event used to initialize a ProtocolFSM.
func Init() Event {
	return Event{Tag: EvtInit}
}

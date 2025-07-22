package protocols

import (
	"code.kerpass.org/golang/internal/transport"
)

// Run synchronously runs protocol p writing/reading messages to/from transport t.
// It returns when p.Update returns a Command with CmdReturn Tag or when an error happens.
func Run(p Protocol, t transport.Transport, h CommandHandler) (any, error) {
	var rmsg, wmsg []byte
	var cmd Command
	var err error
	var rv any
	evt := Init()

cmdloop:
	for {
		cmd, err = p.Update(evt)
		evt = Event{}
		wmsg = nil
		if nil != err {
			return nil, wrapError(err, "failed protocol Update")
		}
		switch cmd.Tag {
		case CmdMessage:
			wmsg = cmd.Msg
		case CmdNoop:
			wmsg = nil
		case CmdReturn:
			wmsg = cmd.Msg
			rv = cmd.Data
			break cmdloop
		default:
			if nil == h {
				return nil, newError("missing handler for command %s", cmd.Tag)
			}
			evt, err = h.Handle(cmd)
			if nil != err {
				return nil, wrapError(err, "failed handling command %s", cmd.Tag)
			}
		}
		if nil != wmsg {
			err = t.WriteBytes(wmsg)
			if nil != err {
				return nil, wrapError(err, "failed transport WriteBytes")
			}
		}
		if "" == evt.Tag {
			rmsg, err = t.ReadBytes()
			if nil != err {
				return nil, wrapError(err, "failed transport ReadBytes")
			}
			evt.Tag = EvtMsg
			evt.Msg = rmsg
		}
	}
	if nil != wmsg {
		err = t.WriteBytes(wmsg)
		if nil != err {
			return nil, wrapError(err, "failed transport WriteBytes")
		}
	}

	return rv, nil
}

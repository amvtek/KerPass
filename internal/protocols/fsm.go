package protocols

type selector interface {
	~int
}

type StateM[Sel selector] interface {
	State() Sel
	SetState(s Sel)
}

type TransitionFunc[Sel selector, S StateM[Sel]] func(s S, evt Event) (Sel, Command, error)

type Transition[Sel selector, S StateM[Sel]] struct {
	Allow []string
	Call  TransitionFunc[Sel, S]
	Exit  []Sel
}

func Update[Sel selector, S StateM[Sel]](s S, trs []Transition[Sel, S], evt Event) (cmd Command, err error) {
	sel := s.State()
	if sel < 0 || int(sel) >= len(trs) {
		return cmd, newError("invalid inner state %s", sel)
	}

	tr := trs[int(sel)]
	var allowed bool
	for _, tag := range tr.Allow {
		if tag == evt.Tag {
			allowed = true
			break
		}
	}
	if !allowed {
		return cmd, newError("Event %s not allowed", evt.Tag)
	}

	if nil != tr.Call {
		sel, cmd, err = tr.Call(s, evt)
	}

	allowed = false
	for _, exit := range tr.Exit {
		if exit == sel {
			allowed = true
			break
		}
	}
	if !allowed {
		return cmd, newError("Exit %s not allowed", sel)
	}

	s.SetState(sel)

	return cmd, err
}

type mysel int

const (
	sInit mysel = iota
	sOne
	sTwo
	countMysel
)

type myStateM struct {
	state mysel
}

func (self *myStateM) State() mysel {
	return self.state
}

func (self *myStateM) SetState(s mysel) {
	self.state = s
}

// This is the main deliverable
// once we have defined a Transition table
// we can use the generic Update to deliver ProtocolFSM implementations.
func (self *myStateM) Update(evt Event) (Command, error) {
	return Update(self, myTransitions[:], evt)
}

var _ ProtocolFSM = &myStateM{}

func (self *myStateM) doUpdate(evt Event) (state mysel, cmd Command, err error) {
	if self.state > 0 {
		return sOne, cmd, err
	} else {
		return sTwo, cmd, err
	}
}

// example Transition table.
var myTransitions = [...]Transition[mysel, *myStateM]{
	sInit: {Call: (*myStateM).doUpdate},
	sOne:  {Call: (*myStateM).doUpdate},
	sTwo:  {Call: (*myStateM).doUpdate},
}

// var _ StateM[mysel, *myState] = &myStateM{}

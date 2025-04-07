package noise

import (
	"strings"
	"sync"
)

var defaultPatternTable *PatternTable

func MustRegisterPattern(dsl string) {
	parts := strings.SplitN(dsl, ":", 2)
	if len(parts) != 2 {
		panic("missing registration name")
	}
	pattern, err := ParsePatternDSL(parts[1])
	if nil != err {
		panic(ErrInvalidPatternDSL)
	}
	err = defaultPatternTable.Register(strings.TrimSpace(parts[0]), pattern)
	if nil != err {
		panic(err)
	}
}

type PatternTable struct {
	mut     sync.RWMutex
	entries map[string]HandshakePattern
}

func NewPatternTable() *PatternTable {
	return &PatternTable{entries: make(map[string]HandshakePattern)}
}

func (self *PatternTable) Register(name string, pattern HandshakePattern) error {
	self.mut.Lock()
	defer self.mut.Unlock()
	_, conflict := self.entries[name]
	if conflict {
		return ErrPatternRegistrationConflict
	}
	self.entries[name] = pattern
	return nil
}

func init() {
	defaultPatternTable = NewPatternTable()

	// 1 way patterns
	MustRegisterPattern(
		`
		N:
		  <- s
		  ...
		  -> e, es
		`,
	)
	MustRegisterPattern(
		`
		K:
		  -> s
		  <- s
		  ...
		  -> e, es, ss
		`,
	)
	MustRegisterPattern(
		`
		X:
		  <- s
		  ...
		  -> e, es, s, ss
		`,
	)

	// interactive patterns
	MustRegisterPattern(
		`
		NN:
		  -> e
		  <- e, ee
		`,
	)
	MustRegisterPattern(
		`
		KN:
		     -> s
		     ...
		     -> e
		     <- e, ee, se
		`,
	)
	MustRegisterPattern(
		`
		NK:
		  <- s
		  ...
		  -> e, es
		  <- e, ee
		`,
	)
	MustRegisterPattern(
		`
		KK:
		     -> s
		     <- s
		     ...
		     -> e, es, ss
		     <- e, ee, se
		`,
	)
	MustRegisterPattern(
		`
		NX:
		  -> e
		  <- e, ee, s, es
		`,
	)
	MustRegisterPattern(
		`
		KX:
		      -> s
		      ...
		      -> e
		      <- e, ee, se, s, es
		`,
	)
	MustRegisterPattern(
		`
		XN:
		  -> e
		  <- e, ee
		  -> s, se
		`,
	)
	MustRegisterPattern(
		`
		IN:
		      -> e, s
		      <- e, ee, se
		`,
	)
	MustRegisterPattern(
		`
		XK:
		  <- s
		  ...
		  -> e, es
		  <- e, ee
		  -> s, se
		`,
	)
	MustRegisterPattern(
		`
		IK:
		      <- s
		      ...
		      -> e, es, s, ss
		      <- e, ee, se
		`,
	)
	MustRegisterPattern(
		`
		XX:
		  -> e
		  <- e, ee, s, es
		  -> s, se
		`,
	)
	MustRegisterPattern(
		`
		IX:
		      -> e, s
		      <- e, ee, se, s, es
		`,
	)
}

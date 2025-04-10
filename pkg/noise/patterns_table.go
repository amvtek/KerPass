package noise

import (
	"strings"
)

var patternRegistry *registry[HandshakePattern]

func MustRegisterPatternSpec(dsl string) {
	parts := strings.SplitN(dsl, ":", 2)
	if len(parts) != 2 {
		panic("missing registration name")
	}
	pattern := HandshakePattern{}
	err := pattern.LoadDSL(parts[1])
	if nil != err {
		panic(err)
	}
	err = registrySet(patternRegistry, strings.TrimSpace(parts[0]), pattern)
	if nil != err {
		panic(err)
	}
}

func RegisterPattern(name string, pattern HandshakePattern) error {
	return registrySet(patternRegistry, name, pattern)
}

func LoadPattern(name string, dst *HandshakePattern) error {
	src, found := registryGet(patternRegistry, name)
	if !found {
		return ErrPatternUnknown
	}
	if nil != dst {
		*dst = src
	}
	return nil
}

func init() {
	patternRegistry = newRegistry[HandshakePattern]()

	// 1 way patterns
	MustRegisterPatternSpec(
		`
		N:
		  <- s
		  ...
		  -> e, es
		`,
	)
	MustRegisterPatternSpec(
		`
		K:
		  -> s
		  <- s
		  ...
		  -> e, es, ss
		`,
	)
	MustRegisterPatternSpec(
		`
		X:
		  <- s
		  ...
		  -> e, es, s, ss
		`,
	)

	// interactive patterns
	MustRegisterPatternSpec(
		`
		NN:
		  -> e
		  <- e, ee
		`,
	)
	MustRegisterPatternSpec(
		`
		KN:
		     -> s
		     ...
		     -> e
		     <- e, ee, se
		`,
	)
	MustRegisterPatternSpec(
		`
		NK:
		  <- s
		  ...
		  -> e, es
		  <- e, ee
		`,
	)
	MustRegisterPatternSpec(
		`
		KK:
		     -> s
		     <- s
		     ...
		     -> e, es, ss
		     <- e, ee, se
		`,
	)
	MustRegisterPatternSpec(
		`
		NX:
		  -> e
		  <- e, ee, s, es
		`,
	)
	MustRegisterPatternSpec(
		`
		KX:
		      -> s
		      ...
		      -> e
		      <- e, ee, se, s, es
		`,
	)
	MustRegisterPatternSpec(
		`
		XN:
		  -> e
		  <- e, ee
		  -> s, se
		`,
	)
	MustRegisterPatternSpec(
		`
		IN:
		      -> e, s
		      <- e, ee, se
		`,
	)
	MustRegisterPatternSpec(
		`
		XK:
		  <- s
		  ...
		  -> e, es
		  <- e, ee
		  -> s, se
		`,
	)
	MustRegisterPatternSpec(
		`
		IK:
		      <- s
		      ...
		      -> e, es, s, ss
		      <- e, ee, se
		`,
	)
	MustRegisterPatternSpec(
		`
		XX:
		  -> e
		  <- e, ee, s, es
		  -> s, se
		`,
	)
	MustRegisterPatternSpec(
		`
		IX:
		      -> e, s
		      <- e, ee, se, s, es
		`,
	)
}

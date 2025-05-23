package noise

import (
	"strings"

	"code.kerpass.org/golang/internal/utils"
)

var patternRegistry *utils.Registry[*HandshakePattern]

// MustRegisterPatternSpec parses dsl which contains name of the pattern and definition of
// the pattern in noise specification language and stores the resulting HandshakePattern in
// the pattern registry. It panics if provided dsl is invalid or if the parsed pattern name
// is already in use.
//
// Refers to noise protocol specs section 7 for a description of the syntax of the language used
// to specify handshakes.
func MustRegisterPatternSpec(dsl string) {
	parts := strings.SplitN(dsl, ":", 2)
	if len(parts) != 2 {
		panic("missing registration name")
	}
	pattern, err := NewPattern(parts[1])
	if nil != err {
		panic(err)
	}
	err = utils.RegistrySet(patternRegistry, strings.TrimSpace(parts[0]), pattern)
	if nil != err {
		panic(err)
	}
}

// RegisterPattern store the pattern in the pattern registry. It errors if name is already
// in use or if the pattern is invalid.
func RegisterPattern(name string, pattern *HandshakePattern) error {
	if nil == pattern {
		return newError("can not register nil pattern")
	}
	return wrapError(
		utils.RegistrySet(patternRegistry, name, pattern),
		"can not register pattern %s",
		name,
	)
}

// LoadPattern copies the pattern referenced by name in dst. It errors if name does
// not correspond to a registered pattern.
func LoadPattern(name string, dst *HandshakePattern) error {
	src, found := utils.RegistryGet(patternRegistry, name)
	if !found || nil == src {
		return newError("unknown pattern %s", name)
	}
	if nil != dst {
		*dst = *src
	}
	return nil
}

func init() {
	patternRegistry = utils.NewRegistry[*HandshakePattern]()

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

	// deferred patterns
	MustRegisterPatternSpec(
		`
		NK1:
		      <- s
		      ...
		      -> e
		      <- e, ee, es
		`,
	)
	MustRegisterPatternSpec(
		`
		NX1:
		      -> e
		      <- e, ee, s
		      -> es
		`,
	)
	MustRegisterPatternSpec(
		`
		X1N:
		      -> e
		      <- e, ee
		      -> s
		      <- se
		`,
	)
	MustRegisterPatternSpec(
		`
		X1K:
		      <- s
		      ...
		      -> e, es
		      <- e, ee
		      -> s
		      <- se
		`,
	)
	MustRegisterPatternSpec(
		`
		XK1:
		      <- s
		      ...
		      -> e
		      <- e, ee, es
		      -> s, se
		`,
	)
	MustRegisterPatternSpec(
		`
		X1K1:
		      <- s
		      ...
		      -> e
		      <- e, ee, es
		      -> s
		      <- se
		`,
	)
	MustRegisterPatternSpec(
		`
		X1X:
		      -> e
		      <- e, ee, s, es
		      -> s
		      <- se
		`,
	)
	MustRegisterPatternSpec(
		`
		XX1:
		      -> e
		      <- e, ee, s
		      -> es, s, se
		`,
	)
	MustRegisterPatternSpec(
		`
		X1X1:
		      -> e
		      <- e, ee, s
		      -> es, s
		      <- se
		`,
	)
	MustRegisterPatternSpec(
		`
		K1N:
		      -> s
		      ...
		      -> e
		      <- e, ee
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		K1K:
		      -> s
		      <- s
		      ...
		      -> e, es
		      <- e, ee
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		KK1:
		      -> s
		      <- s
		      ...
		      -> e
		      <- e, ee, se, es
		`,
	)
	MustRegisterPatternSpec(
		`
		K1K1:
		      -> s
		      <- s
		      ...
		      -> e
		      <- e, ee, es
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		K1X:
		      -> s
		      ...
		      -> e
		      <- e, ee, s, es
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		KX1:
		      -> s
		      ...
		      -> e
		      <- e, ee, se, s
		      -> es
		`,
	)
	MustRegisterPatternSpec(
		`
		K1X1:
		      -> s
		      ...
		      -> e
		      <- e, ee, s
		      -> se, es
		`,
	)
	MustRegisterPatternSpec(
		`
		I1N:
		      -> e, s
		      <- e, ee
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		I1K:
		      <- s
		      ...
		      -> e, es, s
		      <- e, ee
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		IK1:
		      <- s
		      ...
		      -> e, s
		      <- e, ee, se, es
		`,
	)
	MustRegisterPatternSpec(
		`
		I1K1:
		      <- s
		      ...
		      -> e, s
		      <- e, ee, es
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		I1X:
		      -> e, s
		      <- e, ee, s, es
		      -> se
		`,
	)
	MustRegisterPatternSpec(
		`
		IX1:
		      -> e, s
		      <- e, ee, se, s
		      -> es
		`,
	)
	MustRegisterPatternSpec(
		`
		I1X1:
		      -> e, s
		      <- e, ee, s
		      -> se, es
		`,
	)
}

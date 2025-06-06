package noise

import (
	"fmt"
	"iter"
	"slices"
	"strings"
)

const (
	alice = "->"
	left  = "->"

	bob   = "<-"
	right = "<-"

	valid_tokens  = "e s ee es se ss psk"
	valid_senders = "-> <-"
)

// HandshakePattern holds informations that defines a noise protocol handshake.
type HandshakePattern struct {
	premsgs   [2]msgPtrn
	msgs      []msgPtrn
	oneway    bool
	initspecs [2][]initSpec
}

// NewPattern parses dsl that contains a noise protocol handshake description and constructs
// the corresponding HandshakePattern. It errors if provided dsl is invalid.
//
// Refers to noise protocol specs section 7 for a description of the syntax of the language used
// to define handshakes.
//
// You should not normally use NewPattern to create the HandshakePattern{} you need.
// LoadPattern or Config.Load allows you to obtain or safely modify one of the preverified patterns
// referenced in the noise protocol specs.
func NewPattern(dsl string) (*HandshakePattern, error) {
	preMsgs := make([]msgPtrn, 0, 2)
	msgs := make([]msgPtrn, 0, 4)
	preAllow := true

	var ptrn msgPtrn
	var prevSender, sender, token string
	var ptrnTokens, tokens []string
	for msgdsl := range strings.Lines(dsl) {
		tokens = strings.Fields(strings.ReplaceAll(msgdsl, ",", " "))

		// skip if empty line
		if len(tokens) == 0 {
			continue
		}

		sender = tokens[0]
		if sender == prevSender {
			return nil, newError("invalid pattern DSL")
		}
		if "..." == sender {
			// error if '...' was already encountered or if we have more than 2 pre messages or ...
			if !preAllow || len(msgs) > 2 || len(tokens) > 1 {
				return nil, newError("invalid pattern DSL")
			}
			preAllow = false
			preMsgs = append(preMsgs, msgs...)
			msgs = msgs[:0]
			prevSender = ""
			continue
		}

		ptrn = msgPtrn{}
		ptrnTokens = make([]string, 0, 4)
		ptrn.sender = sender
		prevSender = sender

		for _, token = range tokens[1:] {
			switch token {
			case "e", "s":
			case "ee", "es", "se", "ss":
				preAllow = false // DH operation can not be inside pre message
			case "psk":
				preAllow = false // psk can not be inside pre message
			default:
				return nil, newError("invalid token %s", token)
			}
			ptrnTokens = append(ptrnTokens, token)

		}
		ptrn.tokens = ptrnTokens
		msgs = append(msgs, ptrn)
	}
	if 0 == len(msgs) {
		return nil, newError("invalid pattern DSL")
	}

	var initiator, responder string
	initiator = msgs[0].sender
	if left == initiator {
		responder = right
	} else {
		responder = left
	}

	rv := HandshakePattern{msgs: msgs}

	// fill premsgs ensuring that initiator pre msg is at index 0...
	rv.premsgs[0].sender = initiator
	rv.premsgs[1].sender = responder
	for _, msg := range preMsgs {
		switch msg.sender {
		case initiator:
			rv.premsgs[0].tokens = msg.tokens
		case responder:
			rv.premsgs[1].tokens = msg.tokens
		default:
			continue
		}
	}

	err := rv.init()
	if nil != err {
		return nil, wrapError(err, "failed pattern init")
	}

	return &rv, nil
}

// OneWay returns true if the HandshakePattern is one way.
//
// Refers to noise protocol specs section 7.4 for a description of the oneway patterns.
func (self HandshakePattern) OneWay() bool {
	return self.oneway
}

// Dsl returns a string that encodes the HandshakePattern using noise protocol specs pattern definition
// language.
//
// Refers to noise protocol specs section 7 for a description of the syntax of the language used
// to define handshake patterns.
func (self HandshakePattern) Dsl() string {
	lines := make([]string, 0, 4)
	var line string
	for _, msg := range self.premsgs {
		line = msg.Dsl()
		if "" != line {
			lines = append(lines, line)
		}
	}
	if len(lines) > 0 {
		lines = append(lines, "...")
	}
	for _, msg := range self.msgs {
		lines = append(lines, msg.Dsl())
	}
	return strings.Join(lines, "\n")
}

// listInitSpecs returns an initSpec{} iterator which allows validating HandshakeState.Initialize(...) parameters.
func (self *HandshakePattern) listInitSpecs(initiator bool) iter.Seq[initSpec] {
	var roleIdx int
	if initiator {
		roleIdx = 0
	} else {
		roleIdx = 1
	}
	return slices.Values(self.initspecs[roleIdx])
}

// msgPtrns copies the HandshakePattern messages into the dst slice.
func (self HandshakePattern) msgPtrns(dst []msgPtrn) []msgPtrn {
	dst = append(dst, self.msgs...)
	return dst
}

// init validates the HandshakePattern and generates additional informations that
// simplifies later usage.
func (self *HandshakePattern) init() error {
	if nil == self || len(self.msgs) == 0 {
		return newError("invalid pattern")
	}

	validSenders := []string{left, right}
	var initiator, responder string
	var leftIdx, rightIdx int
	initiator = self.msgs[0].sender
	switch initiator {
	case left:
		leftIdx = 0
		rightIdx = 1
		responder = right
	case right:
		leftIdx = 1
		rightIdx = 0
		responder = left
	default:
		return newError("invalid sender %s for initial message", initiator)
	}

	lrTokens := [2][]string{}
	var prevSender, sender string

	// check the premsgs
	var senderIdx int
	for _, msg := range self.premsgs[:] {
		sender = msg.sender
		if prevSender == sender {
			return newError("invalid pattern, premsgs sender %s appears 2 times", sender)
		}
		prevSender = sender
		if !slices.Contains(validSenders, sender) {
			return newError("invalid pattern, premsgs sender %s is invalid", sender)
		}
		if sender == initiator {
			senderIdx = 0
		} else {
			senderIdx = 1
		}
		for token := range msg.Tokens() {
			if slices.Contains(lrTokens[senderIdx], token) {
				return newError("invalid pattern, token %s appears multiple times in premsgs", token)
			}
			switch token {
			case "e", "s":
				lrTokens[senderIdx] = append(lrTokens[senderIdx], token)
			default:
				return newError("invalid pattern, token %s invalid in premsgs", token)
			}
		}
	}

	// reorder the premsgs so that initiator is at index 0
	premsgs := [2]msgPtrn{}
	var tokens []string
	for pos, sender := range []string{initiator, responder} {
		if len(lrTokens[pos]) > 0 {
			tokens = make([]string, len(lrTokens[pos]))
			copy(tokens, lrTokens[pos])
		} else {
			tokens = nil
		}
		premsgs[pos].sender = sender
		premsgs[pos].tokens = tokens
	}

	// check the msgs
	var pskCount int
	lrSTransmits := [2]bool{}
	prevSender = ""
	for _, msg := range self.msgs {
		sender = msg.sender
		if prevSender == sender {
			return newError("invalid pattern, repetion of sender %s in msgs", sender)
		}
		prevSender = sender
		if !slices.Contains(validSenders, sender) {
			return newError("invalid pattern, invalid sender %s in msgs", sender)
		}
		if sender == initiator {
			senderIdx = 0
		} else {
			senderIdx = 1
		}
		for token := range msg.Tokens() {
			if slices.Contains(lrTokens[senderIdx], token) {
				return newError("invalid pattern, token %s appears multiple times in msgs", token)
			}
			switch token {
			case "e":
				lrTokens[senderIdx] = append(lrTokens[senderIdx], token)
			case "s":
				lrSTransmits[senderIdx] = true
				lrTokens[senderIdx] = append(lrTokens[senderIdx], token)
			case "ee", "es", "se", "ss":
				// error if left key was not previously forwarded by left sender
				// spec 7.3.1
				if !slices.Contains(lrTokens[leftIdx], token[:1]) {
					return newError("invalid pattern, missing left %s for %s DH", token[:1], token)
				}
				// error if right key was not previously forwarded by right sender
				// spec 7.3.1
				if !slices.Contains(lrTokens[rightIdx], token[1:]) {
					return newError("invalid pattern, missing right %s for %s DH", token[1:], token)
				}
				lrTokens[senderIdx] = append(lrTokens[senderIdx], token)
			case "psk":
				pskCount += 1
			default:
				return newError("invalid pattern, invalid token %s appears in msgs", token)
			}
		}
	}

	// fill initspecs ensuring that initiator []initSpec is at index 0
	var mp msgPtrn
	var specs []initSpec
	var senderTokens []string
	var pfxtkn string
	var preS bool
	initspecs := [2][]initSpec{}
	numtoken := len(premsgs[0].tokens) + len(premsgs[1].tokens)
	pfxss := [][]string{[]string{"", "r"}, []string{"r", ""}}
	for senderIdx, pfxs := range pfxss {
		specs = make([]initSpec, 0, numtoken)
		preS = false
		for pos, pfx := range pfxs {
			mp = premsgs[pos]
			for tkn := range mp.Tokens() {
				pfxtkn = pfx + tkn
				switch pfxtkn {
				case "s":
					specs = append(specs, initSpec{token: pfxtkn, hash: true, size: 1})
					preS = true // "s" in premsgs[senderIdx]
				case "e", "re", "rs":
					specs = append(specs, initSpec{token: pfxtkn, hash: true, size: 1})
				default:
					continue
				}
			}
		}
		if !preS {
			// "s" not in premsgs[senderIdx] but the protocol may need to forward it
			senderTokens = lrTokens[senderIdx]
			if slices.Contains(senderTokens, "s") {
				specs = append(specs, initSpec{token: "s", size: 1})
			}
		}
		if pskCount > 0 {
			specs = append(specs, initSpec{token: "psk", size: pskCount})
		}

		// check if "s" token will be received by senderIdx
		// in this case, "rs" will need to be verified as it is transmitted...
		if lrSTransmits[(senderIdx+1)%2] {
			specs = append(specs, initSpec{token: "verifiers", size: 1})
		}
		initspecs[senderIdx] = specs
	}

	// determine if the pattern is 1 way
	oneway := false
	if len(self.msgs) == 1 && !slices.Contains(premsgs[0].tokens, "e") && !slices.Contains(premsgs[1].tokens, "e") {
		oneway = true
	}

	self.initspecs = initspecs
	self.premsgs = premsgs
	self.oneway = oneway

	return nil
}

// msgPtrn holds the processing tokens for a certain handshake message.
//
// Refers to noise protocol section 7.1, for details on what msgPtrn{} represents.
type msgPtrn struct {
	sender string
	tokens []string
}

// Tokens returns an iterator yielding the tokens in the msgPtrn.
func (self msgPtrn) Tokens() iter.Seq[string] {
	return slices.Values(self.tokens)
}

// Dsl returns a string that encodes the msgPtrn in noise pattern specification language.
func (self msgPtrn) Dsl() string {
	if len(self.tokens) == 0 {
		return ""
	}
	return fmt.Sprintf("%s %s", self.sender, strings.Join(self.tokens, ", "))
}

// initSpec holds processing instructions for HandshakeState.Initialize method parameter.
type initSpec struct {
	token string
	hash  bool
	size  int
}

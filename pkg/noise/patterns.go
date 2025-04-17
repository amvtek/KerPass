package noise

import (
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

type HandshakePattern struct {
	oneway    bool
	initspecs [2][]initSpec
	premsgs   [2]msgPtrn
	msgs      []msgPtrn
}

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
			return nil, ErrInvalidPatternDSL
		}
		if "..." == sender {
			// error if '...' was already encountered or if we have more than 2 pre messages or ...
			if !preAllow || len(msgs) > 2 || len(tokens) > 1 {
				return nil, ErrInvalidPatternDSL
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
				return nil, ErrInvalidPatternDSL
			}
			ptrnTokens = append(ptrnTokens, token)

		}
		ptrn.tokens = ptrnTokens
		msgs = append(msgs, ptrn)
	}
	if 0 == len(msgs) {
		return nil, ErrInvalidPatternDSL
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
		return nil, err
	}

	return &rv, nil
}

func (self *HandshakePattern) ListInitSpecs(initiator bool) iter.Seq[initSpec] {
	var roleIdx int
	if initiator {
		roleIdx = 0
	} else {
		roleIdx = 1
	}
	return slices.Values(self.initspecs[roleIdx])
}

func (self HandshakePattern) MsgPtrns(dst []msgPtrn) []msgPtrn {
	dst = append(dst, self.msgs...)
	return dst
}

func (self HandshakePattern) OneWay() bool {
	return self.oneway
}

func (self *HandshakePattern) init() error {
	if nil == self || len(self.msgs) == 0 {
		return ErrInvalidHandshakePattern
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
		return ErrInvalidHandshakePattern
	}

	lrTokens := [2][]string{}
	var prevSender, sender string

	// check the premsgs
	var senderIdx int
	for _, msg := range self.premsgs[:] {
		sender = msg.sender
		if prevSender == sender {
			return ErrInvalidHandshakePattern
		}
		prevSender = sender
		if !slices.Contains(validSenders, sender) {
			return ErrInvalidHandshakePattern
		}
		if sender == initiator {
			senderIdx = 0
		} else {
			senderIdx = 1
		}
		for token := range msg.Tokens() {
			if slices.Contains(lrTokens[senderIdx], token) {
				return ErrInvalidMsgPtrnTokenRepeat
			}
			switch token {
			case "e", "s":
				lrTokens[senderIdx] = append(lrTokens[senderIdx], token)
			default:
				return ErrInvalidHandshakePattern
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
	prevSender = ""
	for _, msg := range self.msgs {
		sender = msg.sender
		if prevSender == sender {
			return ErrInvalidHandshakePattern
		}
		prevSender = sender
		if !slices.Contains(validSenders, sender) {
			return ErrInvalidHandshakePattern
		}
		if sender == initiator {
			senderIdx = 0
		} else {
			senderIdx = 1
		}
		for token := range msg.Tokens() {
			if slices.Contains(lrTokens[senderIdx], token) {
				return ErrInvalidMsgPtrnTokenRepeat
			}
			switch token {
			case "e", "s":
				lrTokens[senderIdx] = append(lrTokens[senderIdx], token)
			case "ee", "es", "se", "ss":
				// error if left key was not previously forwarded by left sender
				// spec 7.3.1
				if !slices.Contains(lrTokens[leftIdx], token[:1]) {
					return ErrInvalidHandshakePattern
				}
				// error if right key was not previously forwarded by right sender
				// spec 7.3.1
				if !slices.Contains(lrTokens[rightIdx], token[1:]) {
					return ErrInvalidHandshakePattern
				}
				lrTokens[senderIdx] = append(lrTokens[senderIdx], token)
			case "psk":
				pskCount += 1
			default:
				return ErrInvalidHandshakePattern
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

type msgPtrn struct {
	sender string
	tokens []string
}

func (self msgPtrn) Check() error {
	validSenders := strings.Fields(valid_senders)
	if slices.Index(validSenders, self.sender) == -1 {
		return ErrInvalidMsgPtrnSender
	}

	validTokens := strings.Fields(valid_tokens)
	allTokens := make([]string, 0, len(self.tokens))
	for _, token := range self.tokens {
		if !slices.Contains(validTokens, token) {
			return ErrInvalidMsgPtrnToken
		}
		if slices.Contains(allTokens, token) {
			return ErrInvalidMsgPtrnTokenRepeat
		}
		allTokens = append(allTokens, token)
	}
	return nil
}

func (self msgPtrn) Tokens() iter.Seq[string] {
	return slices.Values(self.tokens)
}

func (self *msgPtrn) Append(tkn string) {
	tokens := make([]string, 0, 1+len(self.tokens))
	tokens = append(tokens, self.tokens...)
	tokens = append(tokens, tkn)
	self.tokens = tokens
}

func (self *msgPtrn) Prepend(tkn string) {
	tokens := make([]string, 0, 1+len(self.tokens))
	tokens = append(tokens, tkn)
	tokens = append(tokens, self.tokens...)
	self.tokens = tokens
}

type initSpec struct {
	token string
	hash  bool
	size  int
}

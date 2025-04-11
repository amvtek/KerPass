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
	initspecs [2][]initSpec
	premsgs   [2]msgPtrn
	msgs      []msgPtrn
}

func (self *HandshakePattern) LoadDSL(dsl string) error {
	leftTokens := make([]string, 0, 12)
	rightTokens := make([]string, 0, 12)
	preMsgs := make([]msgPtrn, 0, 2)
	msgs := make([]msgPtrn, 0, 4)
	preAllow := true

	var ptrn msgPtrn
	var prevSender, sender, token string
	var ptrnTokens, senderTokens, tokens, psks []string
	for msgdsl := range strings.Lines(dsl) {
		tokens = strings.Fields(strings.ReplaceAll(msgdsl, ",", " "))

		// skip if empty line
		if len(tokens) == 0 {
			continue
		}

		ptrn = msgPtrn{}
		ptrnTokens = make([]string, 0, 4)

		sender = tokens[0]
		if sender == prevSender {
			return ErrInvalidPatternDSL
		}
		if "..." == sender {
			// error if '...' was already encountered or if we have more than 2 pre messages or ...
			if !preAllow || len(msgs) > 2 || len(tokens) > 1 {
				return ErrInvalidPatternDSL
			}
			preAllow = false
			preMsgs = append(preMsgs, msgs...)
			msgs = msgs[:0]
			prevSender = ""
			continue
		}
		ptrn.sender = sender
		prevSender = sender

		for _, token = range tokens[1:] {
			switch token {
			// TODO: no enforcement of spec 7.3.4 currently
			case "e", "s":
				// error if same key was previously sent
				// spec 7.3.2
				if slices.Contains(senderTokens, token) {
					return ErrInvalidMsgPtrnTokenRepeat
				}
			case "ee", "es", "se", "ss":
				// error if same DH operation was previously run
				// spec 7.3.3
				if slices.Contains(senderTokens, token) {
					return ErrInvalidMsgPtrnTokenRepeat
				}
				// error if left key was not previously forwarded by left sender
				// spec 7.3.1
				if !slices.Contains(leftTokens, token[:1]) {
					return ErrInvalidPatternDSL
				}
				// error if right key was not previously forwarded by right sender
				// spec 7.3.1
				if !slices.Contains(rightTokens, token[1:]) {
					return ErrInvalidPatternDSL
				}
				preAllow = false // DH operation can not be inside pre message
			case "psk":
				preAllow = false // psk can not be inside pre message
				psks = append(psks, "psk")
			default:
				return ErrInvalidPatternDSL
			}
			ptrnTokens = append(ptrnTokens, token)
			switch sender {
			case left:
				leftTokens = append(leftTokens, token)
			case right:
				rightTokens = append(rightTokens, token)
			default:
				return ErrInvalidMsgPtrnSender
			}

		}
		ptrn.tokens = ptrnTokens
		msgs = append(msgs, ptrn)
	}
	if 0 == len(msgs) {
		return ErrInvalidPatternDSL
	}

	var numtoken int
	var initiator, peer string
	var roleTokenss [][]string
	initiator = msgs[0].sender
	if left == initiator {
		peer = right
		roleTokenss = [][]string{leftTokens, rightTokens}
	} else {
		peer = left
		roleTokenss = [][]string{rightTokens, leftTokens}
	}

	// fill premsgs ensuring that initiator pre msg is at index 0...
	self.premsgs[0] = msgPtrn{sender: initiator}
	self.premsgs[1] = msgPtrn{sender: peer}
	for _, msg := range preMsgs {
		switch msg.sender {
		case initiator:
			self.premsgs[0].tokens = msg.tokens
			numtoken += len(msg.tokens)
		case peer:
			self.premsgs[1].tokens = msg.tokens
			numtoken += len(msg.tokens)
		default:
			continue
		}
	}

	// fill initspecs ensuring that initiator []initSpec is at index 0
	var mp msgPtrn
	var specs []initSpec
	var roleTokens []string
	var pfxtkn string
	var preS bool
	pfxss := [][]string{[]string{"", "r"}, []string{"r", ""}}
	for roleIdx, pfxs := range pfxss {
		specs = make([]initSpec, 0, numtoken)
		preS = false
		for pos, pfx := range pfxs {
			mp = self.premsgs[pos]
			for tkn := range mp.Tokens() {
				pfxtkn = pfx + tkn
				switch pfxtkn {
				case "s":
					specs = append(specs, initSpec{token: pfxtkn, hash: true, size: 1})
					preS = true // "s" in premsgs[roleIdx]
				case "e", "re", "rs":
					specs = append(specs, initSpec{token: pfxtkn, hash: true, size: 1})
				default:
					continue
				}
			}
		}
		if !preS {
			// "s" not in premsgs[roleIdx] but the protocol may need to forward it
			roleTokens = roleTokenss[roleIdx]
			if slices.Contains(roleTokens, "s") {
				specs = append(specs, initSpec{token: "s", size: 1})
			}
		}
		if len(psks) > 0 {
			specs = append(specs, initSpec{token: "psk", size: len(psks)})
		}
		self.initspecs[roleIdx] = specs
	}

	self.msgs = msgs
	return nil

}

func (self HandshakePattern) MsgPtrns(dst []msgPtrn) []msgPtrn {
	dst = append(dst, self.msgs...)
	return dst
}

func (self HandshakePattern) PubkeyHashTokens(initiator bool) (iter.Seq[string], error) {
	// if self was initialized using LoadDSL
	// then premsgs has length 2 & premsgs[0] has initiator sender...
	if 2 != len(self.premsgs) {
		return nil, ErrInvalidHandshakePattern
	}

	var mp msgPtrn
	acc := make([]string, 0, 4)

	var pfxs []string
	if initiator {
		pfxs = []string{"", "r"}
	} else {
		pfxs = []string{"r", ""}
	}
	for pos, pfx := range pfxs {
		mp = self.premsgs[pos]
		for tkn := range mp.Tokens() {
			switch tkn {
			case "e", "s":
				acc = append(acc, pfx+tkn)
			default:
				continue
			}
		}
	}

	return slices.Values(acc), nil
}

func (self HandshakePattern) Check() error {
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

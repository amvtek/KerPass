package noise

import (
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
	prereqs  []msgPtrn
	messages []msgPtrn
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

	prereqs := make([]msgPtrn, 2)
	var roleIdx int
	var prefix string
	for _, role := range []string{left, right} {
		if role == msgs[0].sender {
			roleIdx = 0
		} else {
			roleIdx = 1
		}
		prereqs[roleIdx].sender = role
		tokens = make([]string, 0, 4)
		for _, pmsg := range preMsgs {
			if pmsg.sender == role {
				prefix = ""
			} else {
				prefix = "r"
			}
			for _, token := range pmsg.tokens {
				tokens = append(tokens, prefix+token)
			}
		}
		if !slices.Contains(tokens, "s") {
			switch role {
			case left:
				if slices.Contains(leftTokens, "s") {
					tokens = append(tokens, "s")
				}
			case right:
				if slices.Contains(rightTokens, "s") {
					tokens = append(tokens, "s")
				}
			}
		}
		tokens = append(tokens, psks...)
		slices.Sort(tokens) // ease testing
		prereqs[roleIdx].tokens = tokens
	}
	self.prereqs = prereqs
	self.messages = msgs
	return nil

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

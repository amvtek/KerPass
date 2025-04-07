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
	preMessages []msgPtrn
	messages    []msgPtrn
}

func ParsePatternDSL(dsl string) (HandshakePattern, error) {
	result := HandshakePattern{}
	leftTokens := make([]string, 0, 12)
	rightTokens := make([]string, 0, 12)
	preMsgs := make([]msgPtrn, 0, 2)
	msgs := make([]msgPtrn, 0, 4)
	preAllow := true

	var ptrn msgPtrn
	var prevSender, sender, token string
	var ptrnTokens, senderTokens, tokens []string
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
			return result, ErrInvalidPatternDSL
		}
		if "..." == sender {
			// error if '...' was already encountered or if we have more than 2 pre messages or ...
			if len(result.preMessages) > 0 || len(msgs) > 2 || len(tokens) > 1 || !preAllow {
				return result, ErrInvalidPatternDSL
			}
			result.preMessages = append(preMsgs, msgs...)
			msgs = msgs[:0]
			prevSender = ""
			continue
		}
		ptrn.sender = sender
		prevSender = sender

		for _, token = range tokens[1:] {
			switch token {
			case "e", "s":
				// error if same key was previously sent
				if slices.Index(senderTokens, token) != -1 {
					return result, ErrInvalidMsgPtrnTokenRepeat
				}
			case "ee", "es", "se", "ss":
				// error if same DH operation was previously run
				if slices.Index(senderTokens, token) != -1 {
					return result, ErrInvalidMsgPtrnTokenRepeat
				}
				// error if left key was not previously forwarded by left sender
				if slices.Index(leftTokens, token[:1]) == -1 {
					return result, ErrInvalidPatternDSL
				}
				// error if right key was not previously forwarded by right sender
				if slices.Index(rightTokens, token[1:]) == -1 {
					return result, ErrInvalidPatternDSL
				}
				preAllow = false // DH operation can not be inside pre message
			case "psk":
				preAllow = false // psk can not be inside pre message
			default:
				return result, ErrInvalidPatternDSL
			}
			ptrnTokens = append(ptrnTokens, token)
			switch sender {
			case left:
				leftTokens = append(leftTokens, token)
			case right:
				rightTokens = append(rightTokens, token)
			default:
				return result, ErrInvalidMsgPtrnSender
			}

		}
		ptrn.tokens = ptrnTokens
		msgs = append(msgs, ptrn)
	}
	result.messages = msgs
	return result, nil

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
		if slices.Index(validTokens, token) == -1 {
			return ErrInvalidMsgPtrnToken
		}
		if slices.Index(allTokens, token) != -1 {
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

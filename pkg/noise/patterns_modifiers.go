package noise

import (
	"strconv"
	"strings"
)

const (
	beforeFirst = 0
	afterLast   = -1
)

// PatternModifier is an interface that allows modifying HandshakePattern.
type PatternModifier interface {
	Modify(ptrn HandshakePattern) (HandshakePattern, error)
}

// GetModifier allows retrieving a PatternModifier by name. It errors if the provided name is invalid.
func GetModifier(name string) (PatternModifier, error) {
	switch {
	case strings.HasPrefix(name, "psk"):
		num, err := strconv.ParseUint(name[3:], 10, 8)
		if nil != err {
			return nil, newError("invalid modifier %s", name)
		}
		return pskModifier{pos: uint(num)}, nil
	case name == "fallback":
		return fallbackModifier{}, nil
	default:
		return nil, newError("invalid modifier %s", name)
	}
}

// pskModifier is a PatternModifier that allows mixing a psk in a noise protocol handshake.
type pskModifier struct {
	pos uint
}

// Modify returns a modified HandshakePattern.
func (self pskModifier) Modify(ptrn HandshakePattern) (HandshakePattern, error) {
	var msgPos, insertPos int
	if self.pos > 0 {
		msgPos = int(self.pos) - 1
		insertPos = afterLast
	} else {
		msgPos = 0
		insertPos = beforeFirst
	}

	if msgPos >= len(ptrn.msgs) {
		return ptrn, newError("can not apply psk modifier, no message at %d", msgPos)
	}

	msgs := make([]msgPtrn, len(ptrn.msgs))
	copy(msgs, ptrn.msgs)

	currentTokens := msgs[msgPos].tokens
	tokens := make([]string, 0, 1+len(currentTokens))
	switch insertPos {
	case beforeFirst:
		tokens = append(tokens, "psk")
		tokens = append(tokens, currentTokens...)
	case afterLast:
		tokens = append(tokens, currentTokens...)
		tokens = append(tokens, "psk")
	}

	msgs[msgPos].tokens = tokens
	ptrn.msgs = msgs

	err := ptrn.init()
	return ptrn, err
}

// fallbackModifier is a PatternModifier that allows continuing a failed pattern...
type fallbackModifier struct{}

// Modify returns a modified HandshakePattern.
func (_ fallbackModifier) Modify(ptrn HandshakePattern) (HandshakePattern, error) {
	if len(ptrn.msgs) < 2 {
		return ptrn, newError("can not apply fallback modifier, not enough msgs")
	}
	msg0 := ptrn.msgs[0]

	msgs := make([]msgPtrn, len(ptrn.msgs)-1)
	copy(msgs, ptrn.msgs[1:])
	ptrn.msgs = msgs

	var preIdx int
	for pos, premsg := range ptrn.premsgs {
		if premsg.sender == msg0.sender {
			preIdx = pos
			break
		}
	}

	tokens := make([]string, 0, len(ptrn.premsgs[preIdx].tokens)+len(msg0.tokens))
	tokens = append(tokens, ptrn.premsgs[preIdx].tokens...)
	tokens = append(tokens, msg0.tokens...)
	ptrn.premsgs[preIdx].tokens = tokens

	err := ptrn.init()
	return ptrn, err
}

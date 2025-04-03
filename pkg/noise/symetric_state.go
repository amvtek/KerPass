package noise

import (
	"regexp"
	"strings"
)

var (
	handshakePatternRe = regexp.MustCompile(`^(?P<main>[A-Z][A-Z0-9]*)(?P<mod>[a-z][a-z0-9+]?)?`)
	nameRe             = regexp.MustCompile(`[A-Za-z0-9/]+`)
)

type NoiseProto struct {
	HandshakePattern          string
	HandshakePatternModifiers []string
	DhAlgo                    string
	CipherAlgo                string
	HashAlgo                  string
}

func parseProtocol(srzproto string, proto *NoiseProto) error {
	parts := strings.Split(srzproto, "_")
	if len(parts) != 5 || "Noise" != parts[0] {
		return ErrInvalidProtocolName
	}

	// HandshakePattern
	re := handshakePatternRe
	if !re.MatchString(parts[1]) {
		return ErrInvalidProtocolName
	}
	patparts := re.FindStringSubmatch(parts[1])
	if len(patparts) != 3 || "" == patparts[1] {
		return ErrInvalidProtocolName
	}
	proto.HandshakePattern = patparts[1]
	if "" != patparts[2] {
		proto.HandshakePatternModifiers = strings.Split(patparts[2], "+")
	}

	re = nameRe

	// DhAlgo
	if !re.MatchString(parts[2]) {
		return ErrInvalidProtocolName
	}
	proto.DhAlgo = parts[2]

	// CipherAlgo
	if !re.MatchString(parts[3]) {
		return ErrInvalidProtocolName
	}
	proto.CipherAlgo = parts[3]

	// HashAlgo
	if !re.MatchString(parts[4]) {
		return ErrInvalidProtocolName
	}
	proto.HashAlgo = parts[4]

	return nil
}

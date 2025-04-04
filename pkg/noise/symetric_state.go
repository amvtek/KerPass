package noise

import (
	"regexp"
	"strings"
)

var (
	protoRe = regexp.MustCompile(
		`Noise_([A-Z0-9]+)([a-z][a-z0-9+]*)?_([A-Za-z0-9/]+)_([A-Za-z0-9/]+)_([A-Za-z0-9/]+)`,
	)
)

type NoiseProto struct {
	HandshakePattern          string
	HandshakePatternModifiers []string
	DhAlgo                    string
	CipherAlgo                string
	HashAlgo                  string
}

func ParseProtocol(srzproto string, proto *NoiseProto) (string, error) {
	parts := protoRe.FindStringSubmatch(srzproto)
	if len(parts) != 6 {
		return "", ErrInvalidProtocolName
	}
	if nil == proto {
		return parts[0], nil
	}

	proto.HandshakePattern = parts[1]
	if "" != parts[2] {
		proto.HandshakePatternModifiers = strings.Split(parts[2], "+")
	}
	proto.DhAlgo = parts[3]
	proto.CipherAlgo = parts[4]
	proto.HashAlgo = parts[5]

	return parts[0], nil
}

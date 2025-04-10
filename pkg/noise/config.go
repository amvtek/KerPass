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

type Config struct {
	ProtoName        string
	HandshakePattern HandshakePattern
	CipherFactory    AEADFactory
	HashAlgo         Hash
	DhAlgo           DH
}

func (self *Config) Load(srzproto string) error {
	var proto NoiseProto
	err := ParseProtocol(srzproto, &proto)
	if nil != err {
		return err
	}

	// TODO: needs to modify handshakePattern applying modifiers if any
	handshakePattern := HandshakePattern{}
	err = LoadPattern(proto.HandshakePattern, &handshakePattern)
	if nil != err {
		return err
	}

	cipherFactory, err := GetAEADFactory(proto.CipherAlgo)
	if nil != err {
		return err
	}

	hashAlgo, err := GetHash(proto.HashAlgo)
	if nil != err {
		return err
	}

	dhAlgo, err := GetDH(proto.DhAlgo)
	if nil != err {
		return err
	}

	self.ProtoName = proto.Name
	self.HandshakePattern = handshakePattern
	self.CipherFactory = cipherFactory
	self.HashAlgo = hashAlgo
	self.DhAlgo = dhAlgo

	return nil
}

type NoiseProto struct {
	Name                      string
	HandshakePattern          string
	HandshakePatternModifiers []string
	DhAlgo                    string
	CipherAlgo                string
	HashAlgo                  string
}

func ParseProtocol(srzproto string, proto *NoiseProto) error {
	parts := protoRe.FindStringSubmatch(srzproto)
	if len(parts) != 6 {
		return ErrInvalidProtocolName
	}
	if nil == proto {
		return nil
	}

	proto.HandshakePattern = parts[1]
	if "" != parts[2] {
		proto.HandshakePatternModifiers = strings.Split(parts[2], "+")
	}
	proto.Name = parts[0]
	proto.DhAlgo = parts[3]
	proto.CipherAlgo = parts[4]
	proto.HashAlgo = parts[5]

	return nil
}

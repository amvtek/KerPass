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

// Config holds noise protocol handshake configuration
type Config struct {
	// "name" of the noise protocol, eg "Noise_XX_25519_AESGCM_SHA256".
	// Refers to noise protocol specs section 8, for details on how valid names are formed.
	ProtoName string

	// object that defines how to process the handshake messages.
	HandshakePattern HandshakePattern

	// handshake cipher factory.
	CipherFactory AEADFactory

	// handshake Hash algorithm.
	HashAlgo Hash

	// handshake key exchange algorithm.
	DhAlgo DH
}

// Load parse protoname and loads the algorithms it references into the Config.
//
// Valid protoname looks like "Noise_XX_25519_AESGCM_SHA256".
// Refers to noise protocol specs section 8, for details on how valid names are formed.
func (self *Config) Load(protoname string) error {
	var proto NoiseProto
	err := ParseProtocol(protoname, &proto)
	if nil != err {
		return wrapError(err, "failed ParseProtocol")
	}

	handshakePattern := HandshakePattern{}
	err = LoadPattern(proto.HandshakePattern, &handshakePattern)
	if nil != err {
		return wrapError(err, "failed LoadPattern")
	}
	var md PatternModifier
	for _, mname := range proto.HandshakePatternModifiers {
		md, err = GetModifier(mname)
		if nil != err {
			return wrapError(err, "failed modifier retrieval")
		}
		handshakePattern, err = md.Modify(handshakePattern)
		if nil != err {
			return wrapError(err, "failed applying pattern modifier")
		}
	}

	cipherFactory, err := GetAEADFactory(proto.CipherAlgo)
	if nil != err {
		return wrapError(err, "failed retrieving AEAD factory")
	}

	hashAlgo, err := GetHash(proto.HashAlgo)
	if nil != err {
		return wrapError(err, "failed retrieving Hash algorithm")
	}

	dhAlgo, err := GetDH(proto.DhAlgo)
	if nil != err {
		return wrapError(err, "failed retrieving DH algorithm")
	}

	self.ProtoName = proto.Name
	self.HandshakePattern = handshakePattern
	self.CipherFactory = cipherFactory
	self.HashAlgo = hashAlgo
	self.DhAlgo = dhAlgo

	return nil
}

// NoiseProto holds the components of valid noise protocol names.
// Refers to noise protocol specs section 8, for details on how valid names are formed.
type NoiseProto struct {
	Name                      string
	HandshakePattern          string
	HandshakePatternModifiers []string
	DhAlgo                    string
	CipherAlgo                string
	HashAlgo                  string
}

// ParseProtocol extracts the noise protocol name components and stores them into proto.
//
// Valid protoname looks like "Noise_XX_25519_AESGCM_SHA256".
// Refers to noise protocol specs section 8, for details on how valid names are formed.
func ParseProtocol(protoname string, proto *NoiseProto) error {
	parts := protoRe.FindStringSubmatch(protoname)
	if len(parts) != 6 {
		return newError("Invalid protocol name %s", protoname)
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

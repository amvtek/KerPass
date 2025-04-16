package noise

import (
	"encoding/json"
	"os"

	"dev.kerpass.org/kernel/internal/utils"
)

type TestVector struct {
	ProtocolName                string            `json:"protocol_name"`
	InitiatorPrologue           utils.HexBinary   `json:"init_prologue"`
	InitiatorEphemeralKey       utils.HexBinary   `json:"init_ephemeral"`
	InitiatorStaticKey          utils.HexBinary   `json:"init_static"`
	InitiatorRemoteEphemeralKey utils.HexBinary   `json:"init_remote_ephemeral"`
	InitiatorRemoteStaticKey    utils.HexBinary   `json:"init_remote_static"`
	InitiatorPsks               []utils.HexBinary `json:"init_psks"`
	ResponderPrologue           utils.HexBinary   `json:"resp_prologue"`
	ResponderEphemeralKey       utils.HexBinary   `json:"resp_ephemeral"`
	ResponderStaticKey          utils.HexBinary   `json:"resp_static"`
	ResponderRemoteEphemeralKey utils.HexBinary   `json:"resp_remote_ephemeral"`
	ResponderRemoteStaticKey    utils.HexBinary   `json:"resp_remote_static"`
	ResponderPsks               []utils.HexBinary `json:"resp_psks"`
	HandshakeHash               utils.HexBinary   `json:"handshake_hash"`
	Messages                    []TestMessage     `json:"messages"`
}

type TestMessage struct {
	Payload    utils.HexBinary `json:"payload"`
	CipherText utils.HexBinary `json:"ciphertext"`
}

func LoadTestVectors(srcpath string) ([]TestVector, error) {
	src, err := os.Open(srcpath)
	if nil != err {
		return nil, err
	}
	dec := json.NewDecoder(src)
	s1 := struct {
		Vectors []TestVector `json:"vectors"`
	}{}
	err = dec.Decode(&s1)
	return s1.Vectors, err
}

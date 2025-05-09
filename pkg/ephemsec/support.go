package ephemsec

import (
	"encoding/json"
	"os"

	"code.kerpass.org/golang/internal/utils"
)

// TestVector holds KerPass EPHEMSEC test vector fields.
type TestVector struct {
	SchemeName               string          `json:"scheme"`
	Context                  utils.HexBinary `json:"context"`
	Psk                      utils.HexBinary `json:"psk"`
	SharedSecret             utils.HexBinary `json:"shared_secret"`
	Otp                      string          `json:"otp"`
	InitiatorNonce           utils.HexBinary `json:"init_nonce"`
	InitiatorTime            int64           `json:"init_time"`
	InitiatorStaticKey       utils.HexBinary `json:"init_static_key"`
	InitiatorEphemKey        utils.HexBinary `json:"init_ephemeral_key"`
	InitiatorRemoteStaticKey utils.HexBinary `json:"init_remote_static_key"`
	InitiatorRemoteEphemKey  utils.HexBinary `json:"init_remote_ephemeral_key"`
	ResponderTime            int64           `json:"resp_time"`
	ResponderSynchroHint     int             `json:"resp_synchro_hint"`
	ResponderStaticKey       utils.HexBinary `json:"resp_static_key"`
	ResponderEphemKey        utils.HexBinary `json:"resp_ephemeral_key"`
	ResponderRemoteStaticKey utils.HexBinary `json:"resp_remote_static_key"`
	ResponderRemoteEphemKey  utils.HexBinary `json:"resp_remote_ephemeral_key"`
	HkdfSalt                 utils.HexBinary `json:"hkdf_salt"`
	HkdfInfo                 utils.HexBinary `json:"hkdf_info"`
	HkdfSecret               utils.HexBinary `json:"hkdf_secret"`
}

// LoadTestVector loads test vectors from json file at srcpath.
func LoadTestVectors(srcpath string) ([]TestVector, error) {
	src, err := os.Open(srcpath)
	if nil != err {
		return nil, wrapError(err, "failed opening file %s", srcpath)
	}
	dec := json.NewDecoder(src)
	rv := []TestVector{}
	err = dec.Decode(&rv)
	return rv, wrapError(err, "failed decoding json test vectors")
}

package noise

import (
	"reflect"
	"testing"
)

func TestParseProtocol(t *testing.T) {
	testcases := []struct {
		pn     string
		expect NoiseProto
		fail   bool
	}{
		{
			pn:   "Invalid",
			fail: true,
		},
		{
			pn: "Noise_IK1_X25519_AES256_SHA512/256",
			expect: NoiseProto{
				Name:             "Noise_IK1_X25519_AES256_SHA512/256",
				HandshakePattern: "IK1",
				DhAlgo:           "X25519",
				CipherAlgo:       "AES256",
				HashAlgo:         "SHA512/256",
			},
		},
		{
			pn: "garbageNoise_IK1fallback+psk0_X25519_AES256_SHA512/256_garbage",
			expect: NoiseProto{
				Name:                      "Noise_IK1fallback+psk0_X25519_AES256_SHA512/256",
				HandshakePattern:          "IK1",
				HandshakePatternModifiers: []string{"fallback", "psk0"},
				DhAlgo:                    "X25519",
				CipherAlgo:                "AES256",
				HashAlgo:                  "SHA512/256",
			},
		},
	}

	var err error
	var proto NoiseProto
	for pos, tc := range testcases {
		proto = NoiseProto{}
		err = ParseProtocol(tc.pn, &proto)
		if tc.fail {
			if nil == err {
				t.Errorf("case #%d: ParseProtocol does not fail", pos)
			}
			continue
		}
		if !reflect.DeepEqual(proto, tc.expect) {
			t.Errorf("case #%d: Invalid protocol got %+v != %+v", pos, proto, tc.expect)
		}
	}

}

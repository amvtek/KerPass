package algos

import (
	"testing"
)

func TestECDHRegistry(t *testing.T) {
	testcases := []struct {
		name    string
		privkey int
		pubkey  int
		dhsec   int
	}{
		{name: "X25519", privkey: 32, pubkey: 32, dhsec: 32},
		{name: "P256", privkey: 32, pubkey: 65, dhsec: 32},
		{name: "P384", privkey: 48, pubkey: 97, dhsec: 48},
		{name: "P521", privkey: 66, pubkey: 133, dhsec: 66},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			curve, err := GetCurve(tc.name)
			if nil != err {
				t.Fatalf("failed loading Curve %s, got error %v", tc.name, err)
			}
			if tc.privkey != curve.PrivateKeyLen() {
				t.Errorf("failed PrivateKeyLen control, got %d != %d", curve.PrivateKeyLen(), tc.privkey)
			}
			if tc.pubkey != curve.PublicKeyLen() {
				t.Errorf("failed PublicKeyLen control, got %d != %d", curve.PublicKeyLen(), tc.pubkey)
			}
			if tc.dhsec != curve.DHLen() {
				t.Errorf("Failed DHLen control, got %d != %d", curve.DHLen(), tc.dhsec)
			}
		})
	}
}

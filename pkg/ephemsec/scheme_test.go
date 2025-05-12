package ephemsec

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestNewScheme(t *testing.T) {
	testcases := []struct {
		name   string
		expect scheme
		fail   bool
	}{
		{
			name: "Kerpass_SHA512/256_X25519_E2S2_T400_B16_P8",
			expect: scheme{
				H: "SHA512/256", D: "X25519", K: "E2S2",
				T: 400, B: 16, P: 8,
			},
		},
		{
			name: "Kerpass_BLAKE2s_P256_E1S1_T600_B10_P8",
			expect: scheme{
				H: "BLAKE2s", D: "P256", K: "E1S1",
				T: 600, B: 10, P: 8,
			},
		},
		{
			// fail due to missing Kerpass prefix
			name: "Nopass_SHA256_X25519_E1S1_T400_B10_P8",
			fail: true,
		},
		{
			// fail due to E set to 0 in E0S1
			name: "Kerpass_SHA256_X25519_E0S1_T400_B10_P8",
			fail: true,
		},
		{
			// fail due to S set to 0 in E1S0
			name: "Kerpass_SHA256_X25519_E1S0_T400_B10_P8",
			fail: true,
		},
		{
			// fail due to invalid E3S4 (E & S shall be 1 or 2)
			name: "Kerpass_SHA256_X25519_E1S0_T400_B10_P8",
			fail: true,
		},
		{
			// fail due to non supported B
			name: "Kerpass_SHA256_X25519_E1S0_T400_B57_P8",
			fail: true,
		},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			scm, err := NewScheme(tc.name)
			if tc.fail {
				if nil == err {
					t.Fatalf("Expected NewScheme to fail for %s, but it returned nil error", tc.name)
				} else {
					return
				}
			}
			if nil != err {
				t.Fatalf("Failed NewScheme, got error %v", err)
			}
			expect := &tc.expect
			expect.N = tc.name
			err = expect.Init()
			if nil != err {
				t.Fatalf("Failed expect Init, got error %v", err)
			}
			if !reflect.DeepEqual(scm, expect) {
				t.Fatalf("Failed scheme control, got\n%+v\n!=\n%+v", scm, expect)
			}
		})
	}
}

func TestSchemeInit(t *testing.T) {
	testcases := []struct {
		scheme scheme
		fail   bool
	}{
		// OTP schemes
		{scheme: scheme{N: "1", H: "SHA512", D: "P256", K: "E1S1", T: 400, B: 32, P: 8}},
		{scheme: scheme{N: "1", H: "SHA512/256", D: "X25519", K: "E1S2", T: 400, B: 32, P: 11}},
		{scheme: scheme{N: "1", H: "SHA256", D: "P256", K: "E2S2", T: 400, B: 32, P: 5}},
		{scheme: scheme{N: "1", H: "SHA3/256", D: "P384", K: "E1S1", T: 400, B: 16, P: 8}},
		{scheme: scheme{N: "1", H: "SHA3/512", D: "P521", K: "E1S1", T: 400, B: 16, P: 11}},
		{scheme: scheme{N: "1", H: "BLAKE2b", D: "P256", K: "E1S1", T: 400, B: 16, P: 5}},
		{scheme: scheme{N: "1", H: "BLAKE2s", D: "P256", K: "E1S1", T: 400, B: 10, P: 8}},
		{scheme: scheme{N: "1", H: "SHA512", D: "P256", K: "E1S1", T: 400, B: 10, P: 11}},
		{scheme: scheme{N: "1", H: "SHA512", D: "P256", K: "E1S1", T: 400, B: 10, P: 5}},
		// OTK schemes
		{scheme: scheme{N: "1", H: "SHA512", D: "P256", K: "E1S1", T: 400, B: 256, P: 32}},
		{scheme: scheme{N: "1", H: "SHA512", D: "P256", K: "E1S1", T: 400, B: 256, P: 64}},
		// Invalid schemes
		{scheme: scheme{N: "1", H: "BLAKE2b", D: "X25519", K: "E1S1", T: 400, B: 33, P: 8}, fail: true},   // B not supported
		{scheme: scheme{N: "1", H: "BLAKE2b", D: "X25519", K: "E1S1", T: 400, B: 32, P: 14}, fail: true},  // P too large (65 > 64 entropy bits)
		{scheme: scheme{N: "1", H: "BLAKE2b", D: "X25519", K: "E1S1", T: -400, B: 32, P: 11}, fail: true}, // T < 0
		{scheme: scheme{N: "1", H: "BLAKE2b", D: "X25519", K: "E1S1", T: 400, B: 32, P: 0}, fail: true},   // P == 0
		{scheme: scheme{N: "1", H: "BLAKE2b", D: "X25519", K: "E1S1", T: 0, B: 10, P: 6}, fail: true},     // T == 0
		{scheme: scheme{N: "1", H: "FOO", D: "X25519", K: "E1S1", T: 400, B: 10, P: 6}, fail: true},       // H == FOO unsupported
		{scheme: scheme{N: "1", H: "SHA256", D: "XBAR", K: "E1S1", T: 400, B: 10, P: 6}, fail: true},      // D == XBAR unsupported
		{scheme: scheme{N: "1", H: "SHA256", D: "XBAR", K: "E0S1", T: 400, B: 10, P: 6}, fail: true},      // K == E0S1 unsupported
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			err := tc.scheme.Init()
			if tc.fail {
				if nil == err {
					t.Fatalf("#%d: success where fail expected", pos)
				}
			} else {
				if nil != err {
					t.Fatalf("#%d: failed with error %v", pos, err)
				}
			}
			t.Logf("#%d: scheme -> %+v", pos, tc.scheme)
		})
	}
}

func TestSchemeTime(t *testing.T) {
	testcases := []struct {
		scheme  scheme
		reftime string
	}{
		{
			scheme:  scheme{N: "1", H: "BLAKE2s", D: "X25519", K: "E1S1", T: 300, B: 10, P: 7},
			reftime: "2008-03-12T12:45:56Z",
		},
		{
			scheme:  scheme{N: "1", H: "BLAKE2s", D: "X25519", K: "E1S1", T: 400, B: 16, P: 8},
			reftime: "2018-06-06T05:32:07Z",
		},
		{
			scheme:  scheme{N: "1", H: "BLAKE2s", D: "X25519", K: "E1S1", T: 400, B: 32, P: 8},
			reftime: "2025-09-14T11:48:07Z",
		},
		{
			scheme:  scheme{N: "1", H: "BLAKE2s", D: "X25519", K: "E1S1", T: 400, B: 32, P: 11},
			reftime: "2031-10-18T15:38:12Z",
		},
		{
			scheme:  scheme{N: "1", H: "BLAKE2s", D: "X25519", K: "E1S1", T: 1024, B: 256, P: 32},
			reftime: "2031-10-18T15:38:12Z",
		},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			sc := tc.scheme
			err := sc.Init()
			if nil != err {
				t.Fatalf("Failed scheme Init, got error %v", err)
			}
			tp, err := time.Parse(time.RFC3339, tc.reftime)
			if nil != err {
				t.Fatalf("Failed time parsing, got error %v", err)
			}
			rts := tp.Unix()
			pts, _ := sc.Time(rts)
			if math.Abs(float64(rts)-float64(pts)*sc.step) > sc.step {
				t.Fatalf("Failed rts control with rts=%v, pts=%v & step=%v", rts, pts, sc.step)
			}
			// we want to validate that given rts and vts in [rts - T/2 : rts + T/2] range
			// and pts, sync = sc.Time(vts)
			// we can recover pts using sc.SyncTime(rts, sync)
			var vts, pts0, pts1 int64
			var sync int
			halfT := int64(sc.T / 2)
			for dT := range int64(sc.T) {
				vts = rts + dT - halfT
				pts0, sync = sc.Time(vts)
				pts1, err = sc.SyncTime(rts, sync)
				if nil != err {
					t.Errorf("Failed SyncTime for dT=%v, got error %v", dT, err)
				}
				if pts0 != pts1 {
					t.Errorf(
						"With scheme -> %+v\nFailed synchronization for dT=%v rts=%v pts0=%v, pts1=%v",
						sc, dT, rts, pts0, pts1,
					)
				}
			}

		})
	}
}

func TestSchemeMakeOTP(t *testing.T) {
	// TODO: no coverage through this approach for base 256
	testcases := []struct {
		B      int
		P      int
		digits []byte
		PT     int64
	}{
		{B: 10, P: 9, digits: []byte{1, 2, 3, 4, 9, 8, 7, 6}, PT: 5},
		{B: 10, P: 8, digits: []byte{1, 2, 3, 0, 8, 7, 6}, PT: 4},
		{B: 16, P: 10, digits: []byte{15, 14, 13, 12, 11, 10, 9, 8, 7}, PT: 6},
		{B: 32, P: 6, digits: []byte{0, 31, 30, 29, 28}, PT: 7},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			sch := scheme{N: "1", H: "SHA256", D: "P256", K: "E1S2", T: 400}
			sch.B = tc.B
			sch.P = tc.P
			err := sch.Init()
			if nil != err {
				t.Fatalf("Failed sch.Init, got error %v", err)
			}

			// uses digits to calculate corresponding uint64
			b := uint64(tc.B)
			var v, digit uint64
			for _, d := range tc.digits {
				digit = uint64(d)
				v *= b
				v += digit
			}

			// serialize v to []byte
			src := make([]byte, 8)
			binary.BigEndian.PutUint64(src, v)
			otp, err := sch.NewOTP(src, tc.PT)
			if nil != err {
				t.Fatalf("Failed sch.NewOTP, got error %v", err)
			}

			expect := make([]byte, 0, tc.P)
			expect = append(expect, tc.digits...)
			expect = append(expect, byte(tc.PT))
			if !reflect.DeepEqual(otp, expect) {
				t.Errorf("Failed otp control\n%v\n!=\n%v", otp, expect)
			}

		})
	}
}

func FuzzSchemeTime(f *testing.F) {
	testcases := []struct {
		scheme  scheme
		reftime string
	}{
		{
			scheme:  scheme{N: "1", H: "SHA256", D: "P256", K: "E1S1", T: 300, B: 10, P: 7},
			reftime: "2008-03-12T12:45:56Z",
		},
		{
			scheme:  scheme{N: "1", H: "SHA256", D: "X25519", K: "E1S1", T: 400, B: 16, P: 8},
			reftime: "2018-06-06T05:32:07Z",
		},
		{
			scheme:  scheme{N: "1", H: "SHA512", D: "P256", K: "E1S1", T: 400, B: 32, P: 8},
			reftime: "2025-09-14T11:48:07Z",
		},
		{
			scheme:  scheme{N: "1", H: "SHA3/256", D: "P256", K: "E1S1", T: 400, B: 32, P: 11},
			reftime: "2031-10-18T15:38:12Z",
		},
		{
			scheme:  scheme{N: "1", H: "BLAKE2b", D: "X25519", K: "E1S1", T: 1024, B: 256, P: 32},
			reftime: "2031-10-18T15:38:12Z",
		},
	}
	var readtime time.Time
	var err error
	for pos := range len(testcases) {
		err = testcases[pos].scheme.Init()
		if nil != err {
			f.Fatalf("#%d: Failed initializing scheme, got error %v", pos, err)
		}
		readtime, err = time.Parse(time.RFC3339, testcases[pos].reftime)
		if nil != err {
			f.Fatalf("#%d: Failed time parsing, got error %v", pos, err)
		}
		f.Add(readtime.Unix())
	}
	f.Fuzz(func(t *testing.T, ts int64) {
		if ts < 0 {
			ts = -ts
		}
		var err error
		var sc scheme
		var vts, pts0, pts1, halfT int64
		var sync int
		for _, tc := range testcases {
			sc = tc.scheme
			halfT = int64(sc.T / 2)
			for dT := range int64(sc.T) {
				vts = ts + dT - halfT
				pts0, sync = sc.Time(vts)
				pts1, err = sc.SyncTime(ts, sync)
				if nil != err {
					t.Fatalf("Failed SyncTime for dT=%v, got error %v", dT, err)
				}
				if pts0 != pts1 {
					t.Fatalf("Failed synchronization for dT=%v rts=%v pts0=%v, pts1=%v", dT, ts, pts0, pts1)
				}
			}
		}
	})
}

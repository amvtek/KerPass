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
		expect Scheme
		fail   bool
	}{
		{
			name: "Kerpass_SHA512/256_X25519_E2S2_T400B16P8",
			expect: Scheme{
				hn: "SHA512/256", dhn: "X25519", kx: "E2S2",
				tw: 400, eb: 16, nd: 8,
			},
		},
		{
			name: "Kerpass_BLAKE2s_P256_E1S1_T600B10P8",
			expect: Scheme{
				hn: "BLAKE2s", dhn: "P256", kx: "E1S1",
				tw: 600, eb: 10, nd: 8,
			},
		},
		{
			// fail due to missing Kerpass prefix
			name: "Nopass_SHA256_X25519_E1S1_T400B10P8",
			fail: true,
		},
		{
			// fail due to E set to 0 in E0S1
			name: "Kerpass_SHA256_X25519_E0S1_T400B10P8",
			fail: true,
		},
		{
			// fail due to S set to 0 in E1S0
			name: "Kerpass_SHA256_X25519_E1S0_T400B10P8",
			fail: true,
		},
		{
			// fail due to invalid E3S4 (E & S shall be 1 or 2)
			name: "Kerpass_SHA256_X25519_E1S0_T400B10P8",
			fail: true,
		},
		{
			// fail due to non supported B
			name: "Kerpass_SHA256_X25519_E1S0_T400B57P8",
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
			expect.name = tc.name
			err = expect.init()
			if nil != err {
				t.Fatalf("Failed expect.init, got error %v", err)
			}
			if !reflect.DeepEqual(scm, expect) {
				t.Fatalf("Failed scheme control, got\n%+v\n!=\n%+v", scm, expect)
			}
		})
	}
}

func TestSchemeInit(t *testing.T) {
	testcases := []struct {
		scheme Scheme
		fail   bool
	}{
		// OTP schemes
		{scheme: Scheme{name: "1", hn: "SHA512", dhn: "P256", kx: "E1S1", tw: 400, eb: 32, nd: 8}},
		{scheme: Scheme{name: "1", hn: "SHA512/256", dhn: "X25519", kx: "E1S2", tw: 400, eb: 32, nd: 11}},
		{scheme: Scheme{name: "1", hn: "SHA256", dhn: "P256", kx: "E2S2", tw: 400, eb: 32, nd: 5}},
		{scheme: Scheme{name: "1", hn: "SHA3/256", dhn: "P384", kx: "E1S1", tw: 400, eb: 16, nd: 8}},
		{scheme: Scheme{name: "1", hn: "SHA3/512", dhn: "P521", kx: "E1S1", tw: 400, eb: 16, nd: 11}},
		{scheme: Scheme{name: "1", hn: "BLAKE2b", dhn: "P256", kx: "E1S1", tw: 400, eb: 16, nd: 5}},
		{scheme: Scheme{name: "1", hn: "BLAKE2s", dhn: "P256", kx: "E1S1", tw: 400, eb: 10, nd: 8}},
		{scheme: Scheme{name: "1", hn: "SHA512", dhn: "P256", kx: "E1S1", tw: 400, eb: 10, nd: 11}},
		{scheme: Scheme{name: "1", hn: "SHA512", dhn: "P256", kx: "E1S1", tw: 400, eb: 10, nd: 5}},
		// OTK schemes
		{scheme: Scheme{name: "1", hn: "SHA512", dhn: "P256", kx: "E1S1", tw: 400, eb: 256, nd: 32}},
		{scheme: Scheme{name: "1", hn: "SHA512", dhn: "P256", kx: "E1S1", tw: 400, eb: 256, nd: 64}},
		// Invalid schemes
		{scheme: Scheme{name: "1", hn: "BLAKE2b", dhn: "X25519", kx: "E1S1", tw: 400, eb: 33, nd: 8}, fail: true},   // B not supported
		{scheme: Scheme{name: "1", hn: "BLAKE2b", dhn: "X25519", kx: "E1S1", tw: 400, eb: 32, nd: 14}, fail: true},  // P too large (65 > 64 entropy bits)
		{scheme: Scheme{name: "1", hn: "BLAKE2b", dhn: "X25519", kx: "E1S1", tw: -400, eb: 32, nd: 11}, fail: true}, // T < 0
		{scheme: Scheme{name: "1", hn: "BLAKE2b", dhn: "X25519", kx: "E1S1", tw: 400, eb: 32, nd: 0}, fail: true},   // P == 0
		{scheme: Scheme{name: "1", hn: "BLAKE2b", dhn: "X25519", kx: "E1S1", tw: 0, eb: 10, nd: 6}, fail: true},     // T == 0
		{scheme: Scheme{name: "1", hn: "FOO", dhn: "X25519", kx: "E1S1", tw: 400, eb: 10, nd: 6}, fail: true},       // H == FOO unsupported
		{scheme: Scheme{name: "1", hn: "SHA256", dhn: "XBAR", kx: "E1S1", tw: 400, eb: 10, nd: 6}, fail: true},      // D == XBAR unsupported
		{scheme: Scheme{name: "1", hn: "SHA256", dhn: "XBAR", kx: "E0S1", tw: 400, eb: 10, nd: 6}, fail: true},      // K == E0S1 unsupported
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			err := tc.scheme.init()
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
		scheme  Scheme
		reftime string
	}{
		{
			scheme:  Scheme{name: "1", hn: "BLAKE2s", dhn: "X25519", kx: "E1S1", tw: 300, eb: 10, nd: 7},
			reftime: "2008-03-12T12:45:56Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "BLAKE2s", dhn: "X25519", kx: "E1S1", tw: 400, eb: 16, nd: 8},
			reftime: "2018-06-06T05:32:07Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "BLAKE2s", dhn: "X25519", kx: "E1S1", tw: 400, eb: 32, nd: 8},
			reftime: "2025-09-14T11:48:07Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "BLAKE2s", dhn: "X25519", kx: "E1S1", tw: 400, eb: 32, nd: 11},
			reftime: "2031-10-18T15:38:12Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "BLAKE2s", dhn: "X25519", kx: "E1S1", tw: 1024, eb: 256, nd: 32},
			reftime: "2031-10-18T15:38:12Z",
		},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			sc := tc.scheme
			err := sc.init()
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
			halfT := int64(sc.tw / 2)
			for dT := range int64(sc.tw) {
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
		eb     int
		nd     int
		digits []byte
		pt     int64
	}{
		{eb: 10, nd: 9, digits: []byte{1, 2, 3, 4, 9, 8, 7, 6}, pt: 5},
		{eb: 10, nd: 8, digits: []byte{1, 2, 3, 0, 8, 7, 6}, pt: 4},
		{eb: 16, nd: 10, digits: []byte{15, 14, 13, 12, 11, 10, 9, 8, 7}, pt: 6},
		{eb: 32, nd: 6, digits: []byte{0, 31, 30, 29, 28}, pt: 7},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("case#%d", pos), func(t *testing.T) {
			sch := Scheme{name: "1", hn: "SHA256", dhn: "P256", kx: "E1S2", tw: 400}
			sch.eb = tc.eb
			sch.nd = tc.nd
			err := sch.init()
			if nil != err {
				t.Fatalf("Failed sch.Init, got error %v", err)
			}

			// uses digits to calculate corresponding uint64
			b := uint64(tc.eb)
			var v, digit uint64
			for _, d := range tc.digits {
				digit = uint64(d)
				v *= b
				v += digit
			}

			// serialize v to []byte
			src := make([]byte, 8)
			binary.BigEndian.PutUint64(src, v)
			otp, err := sch.NewOTP(src, tc.pt)
			if nil != err {
				t.Fatalf("Failed sch.NewOTP, got error %v", err)
			}

			expect := make([]byte, 0, tc.nd)
			expect = append(expect, tc.digits...)
			expect = append(expect, byte(tc.pt))
			if !reflect.DeepEqual(otp, expect) {
				t.Errorf("Failed otp control\n%v\n!=\n%v", otp, expect)
			}

		})
	}
}

func FuzzSchemeTime(f *testing.F) {
	testcases := []struct {
		scheme  Scheme
		reftime string
	}{
		{
			scheme:  Scheme{name: "1", hn: "SHA256", dhn: "P256", kx: "E1S1", tw: 300, eb: 10, nd: 7},
			reftime: "2008-03-12T12:45:56Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "SHA256", dhn: "X25519", kx: "E1S1", tw: 400, eb: 16, nd: 8},
			reftime: "2018-06-06T05:32:07Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "SHA512", dhn: "P256", kx: "E1S1", tw: 400, eb: 32, nd: 8},
			reftime: "2025-09-14T11:48:07Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "SHA3/256", dhn: "P256", kx: "E1S1", tw: 400, eb: 32, nd: 11},
			reftime: "2031-10-18T15:38:12Z",
		},
		{
			scheme:  Scheme{name: "1", hn: "BLAKE2b", dhn: "X25519", kx: "E1S1", tw: 1024, eb: 256, nd: 32},
			reftime: "2031-10-18T15:38:12Z",
		},
	}
	var readtime time.Time
	var err error
	for pos := range len(testcases) {
		err = testcases[pos].scheme.init()
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
		var sc Scheme
		var vts, pts0, pts1, halfT int64
		var sync int
		for _, tc := range testcases {
			sc = tc.scheme
			halfT = int64(sc.tw / 2)
			for dT := range int64(sc.tw) {
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

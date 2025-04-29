package ephemsec

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func TestSchemeInit(t *testing.T) {
	testcases := []struct {
		scheme Scheme
		fail   bool
	}{
		// OTP schemes
		{scheme: Scheme{pT: 400, pB: 32, pP: 8, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 32, pP: 11, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 32, pP: 5, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 16, pP: 8, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 16, pP: 11, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 16, pP: 5, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 10, pP: 8, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 10, pP: 11, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 10, pP: 5, pS: 1}},
		// OTK schemes
		{scheme: Scheme{pT: 400, pB: 256, pP: 32, pS: 1}},
		{scheme: Scheme{pT: 400, pB: 256, pP: 64, pS: 1}},
		// Invalid schemes
		{scheme: Scheme{pT: 400, pB: 33, pP: 8, pS: 1}, fail: true},   // B not supported
		{scheme: Scheme{pT: 400, pB: 32, pP: 13, pS: 1}, fail: true},  // P too large (65 > 64 entropy bits)
		{scheme: Scheme{pT: -400, pB: 32, pP: 11, pS: 1}, fail: true}, // T < 0
		{scheme: Scheme{pT: 400, pB: 32, pP: 0, pS: 1}, fail: true},   // P == 0
		{scheme: Scheme{pT: 0, pB: 10, pP: 6, pS: 0}, fail: true},     // T == 0
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
		scheme  Scheme
		reftime string
	}{
		{
			scheme:  Scheme{pT: 300, pB: 10, pP: 7, pS: 1},
			reftime: "2008-03-12T12:45:56Z",
		},
		{
			scheme:  Scheme{pT: 400, pB: 16, pP: 8, pS: 1},
			reftime: "2018-06-06T05:32:07Z",
		},
		{
			scheme:  Scheme{pT: 400, pB: 32, pP: 8, pS: 1},
			reftime: "2025-09-14T11:48:07Z",
		},
		{
			scheme:  Scheme{pT: 400, pB: 32, pP: 11, pS: 1},
			reftime: "2031-10-18T15:38:12Z",
		},
		{
			scheme:  Scheme{pT: 1024, pB: 256, pP: 32, pS: 1},
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
			halfT := int64(sc.pT / 2)
			for dT := range int64(sc.pT - sc.step) {
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

func FuzzSchemeTime(f *testing.F) {
	testcases := []struct {
		scheme  Scheme
		reftime string
	}{
		{
			scheme:  Scheme{pT: 300, pB: 10, pP: 7, pS: 1},
			reftime: "2008-03-12T12:45:56Z",
		},
		{
			scheme:  Scheme{pT: 400, pB: 16, pP: 8, pS: 1},
			reftime: "2018-06-06T05:32:07Z",
		},
		{
			scheme:  Scheme{pT: 400, pB: 32, pP: 8, pS: 1},
			reftime: "2025-09-14T11:48:07Z",
		},
		{
			scheme:  Scheme{pT: 400, pB: 32, pP: 11, pS: 1},
			reftime: "2031-10-18T15:38:12Z",
		},
		{
			scheme:  Scheme{pT: 1024, pB: 256, pP: 32, pS: 1},
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
		var sc Scheme
		var vts, pts0, pts1, halfT int64
		var sync int
		for _, tc := range testcases {
			sc = tc.scheme
			halfT = int64(sc.pT / 2)
			for dT := range int64(sc.pT - sc.step) {
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

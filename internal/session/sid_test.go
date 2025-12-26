package session

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestSidFactoryNew(t *testing.T) {
	_, err := NewSidFactory(-10 * time.Second)
	if nil == err {
		t.Error("Could construct SidFactory with lifetime < 0")
	}
	_, err = NewSidFactory(0)
	if nil == err {
		t.Error("Could construct SidFactory with 0 lifetime")
	}
	_, err = NewSidFactory(4 * time.Nanosecond)
	if nil == err {
		t.Error("Could construct SidFactory with lifetime < numSlot")
	}
	sf, err := NewSidFactory(numSlot * time.Nanosecond)
	if nil != err {
		t.Errorf("Failed NewSidFactory, got error %v", err)
	}
	if nil == sf {
		t.Error("Got nil *SidFactory")
	}
}

func TestSidFactoryExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime := 32 * time.Second
		sf, err := NewSidFactory(lifetime)
		if nil != err {
			t.Fatalf("Failed NewSidFactory, got error %v", err)
		}

		time.Sleep(8500 * time.Hour)
		sid := sf.New(0x11223344_55667788)
		t.Logf("sid -> % X", sid)

		time.Sleep(lifetime - 1*time.Nanosecond)
		err = sf.Check(sid)
		if nil != err {
			t.Fatalf("Failed validating sid, got error:\n%v", err)
		}

		time.Sleep(2 * time.Nanosecond)
		err = sf.Check(sid)
		if !errors.Is(err, ErrKeyExpired) {
			t.Fatalf("Failed to detect sid expiration, got error:%v", err)
		}
	})
}

func TestSidFactoryTamper(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime := 48 * time.Second
		sf, err := NewSidFactory(lifetime)
		if nil != err {
			t.Fatalf("Failed NewSidFactory, got error %v", err)
		}

		time.Sleep(22 * time.Hour)
		sid := sf.New(0)
		if nil != err {
			t.Fatalf("Failed generating sid, got error %v", err)
		}
		t.Logf("sid -> % X", sid)
		t.Logf("sid.T() -> %d", sid.T())

		time.Sleep(36 * time.Second)

		// check that sid is still valid
		err = sf.Check(sid)
		if nil != err {
			t.Fatalf("sid found invalid after 32s, got error %v", err)
		}

		// "tamper" the sid
		sid[40] += 1
		err = sf.Check(sid)
		if !errors.Is(err, ErrKeyTampered) {
			t.Fatalf("Failed to detect tampered sid, got error:%v", err)
		}
	})
}

func TestSidAD(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime := 32 * time.Second
		sf, err := NewSidFactory(lifetime)
		if nil != err {
			t.Fatalf("Failed NewSidFactory, got error %v", err)
		}
		time.Sleep(70*8700*time.Hour + 1024*time.Hour + 25*time.Minute)

		var sid Sid
		for i, ad := range []uint64{0, 0x1122, 0x33445566, 0xFF00EE11_DD22CC33} {
			sid = sf.New(ad)
			if ad != sid.AD() {
				t.Errorf("#%d sid.AD() control, %X != %X", i, sid.AD(), ad)
			}
		}
	})
}

func TestSidLog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lifetime := 32 * time.Second
		sf, err := NewSidFactory(lifetime)
		if nil != err {
			t.Fatalf("Failed NewSidFactory, got error %v", err)
		}
		time.Sleep(2 * time.Second)

		var sid Sid
		for i := range 2 {
			sid = sf.New(0xFF00EE11_DD22CC33)
			t.Log("---")
			t.Logf("#%d sid[:32] -> % X", i, sid[:32])
			t.Logf("#%d sid[32:] -> % X", i, sid[32:])
			t.Logf("#%d sid.T() -> %d", i, sid.T())
			t.Logf("#%d sid.C() -> %d", i, sid.C())
			t.Logf("#%d sid.AD() -> %X", i, sid.AD())
			time.Sleep(2 * time.Second)
		}
	})
}

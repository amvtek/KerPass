package session

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestClockInit(t *testing.T) {
	clock := Clock{}

	// error if step == 0
	err := clock.Init(0)
	if nil == err {
		t.Error("Init returned nil error with 0 step")
	}

	// error if step < 0
	err = clock.Init(-10 * time.Second)
	if nil == err {
		t.Error("Init returned nil error with step < 0")
	}

	// no error if step > 0
	err = clock.Init(3 * time.Minute)
	if nil != err {
		t.Errorf("Init failed with step > 0, got error %v", err)
	}
}

func TestClockTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var step time.Duration
		clock := Clock{}

		time.Sleep(48*time.Hour + 20*time.Minute)
		step = 32 * time.Second
		err := clock.Init(step)
		if nil != err {
			t.Fatalf("Failed clock.Init, got error %v", err)
		}

		time.Sleep(step - 1*time.Nanosecond)
		if 0 != clock.T() {
			t.Errorf("clock.T() -> %d != 0", clock.T())
		}
		time.Sleep(1 * time.Nanosecond)
		if 1 != clock.T() {
			t.Errorf("clock.T() -> %d != 1", clock.T())
		}
		time.Sleep(8*step - 1*time.Nanosecond)
		if 8 != clock.T() {
			t.Errorf("clock.T() -> %d != 8", clock.T())
		}
		time.Sleep(1 * time.Nanosecond)
		if 9 != clock.T() {
			t.Errorf("clock.T() -> %d != 9", clock.T())
		}

	})
}

package session

import (
	"time"
)

type Timed interface {
	// T returns a "pseudo time"
	T() int64
}

// Clock is a scaled monotonic clock.
// It increments time by 1 every step nanoseconds.
type Clock struct {
	t0   time.Time
	step int64
}

// Init initializes the Clock.
// It errors if step <= 0
func (self *Clock) Init(step time.Duration) error {
	if step <= 0 {
		return newError("Invalid step %d <= 0", step)
	}

	self.step = int64(step)
	self.t0 = time.Now()

	return nil
}

// T returns the number of step since Init was called.
func (self Clock) T() int64 {
	return time.Since(self.t0).Nanoseconds() / self.step
}

var _ Timed = Clock{}

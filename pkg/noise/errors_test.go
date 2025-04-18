package noise

import (
	"errors"
	"io"
	"testing"
)

func TestErrorFoo(t *testing.T) {
	err := foo()
	t.Logf("err -> %v", err)
	if !errors.Is(err, Error) {
		t.Error("Oops, err is not a noise.Error")
	}
	_, ok := err.(raisedErr)
	if !ok {
		t.Error("Oops, can not cast err to raisedErr")
	}
}

func TestErrorBar(t *testing.T) {
	err := bar()
	t.Logf("err -> %v", err)
	if !errors.Is(err, Error) {
		t.Error("Oops, err is not a noise.Error")
	}
	if !errors.Is(err, io.EOF) {
		t.Error("Oops, err is not an io.EOF")
	}
	_, ok := err.(raisedErr)
	if !ok {
		t.Error("Oops, can not cast err to raisedErr")
	}
}

func TestErrorBaz(t *testing.T) {
	errs := baz()
	for pos, err := range errs {
		t.Logf("#%d: err -> %v", pos, err)
		if !errors.Is(err, Error) {
			t.Errorf("#%d: err is not a noise.Error", pos)
		}
		_, ok := err.(raisedErr)
		if !ok {
			t.Errorf("#%d: can not cast err to raisedErr", pos)
		}
	}
	err := errs[1]
	if !errors.Is(err, io.EOF) {
		t.Error("Oops, err is not an io.EOF")
	}
}

func foo() error {
	return newError("Something bad happened")
}

func bar() error {
	return wrapError(io.EOF, "io operation failed unexpectedly")
}

func baz() []error {
	return []error{
		newError("reached limit temperature %d", 123),
		wrapError(io.EOF, "can not read from %s", "missing.txt"),
	}
}

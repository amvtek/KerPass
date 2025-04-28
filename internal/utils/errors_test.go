package utils

import (
	"errors"
	"io"
	"testing"
)

func TestErrorFoo(t *testing.T) {
	err := foo()
	t.Logf("err -> %v", err)
	if !errors.Is(err, PkgBaseError) {
		t.Error("Oops, err is not PkgBaseError")
	}
	_, ok := err.(RaisedErr)
	if !ok {
		t.Error("Oops, can not cast err to RaisedErr")
	}
}

func TestErrorBar(t *testing.T) {
	err := bar()
	t.Logf("err -> %v", err)
	if !errors.Is(err, PkgBaseError) {
		t.Error("Oops, err is not PkgBaseError")
	}
	if !errors.Is(err, io.EOF) {
		t.Error("Oops, err is not an io.EOF")
	}
	_, ok := err.(RaisedErr)
	if !ok {
		t.Error("Oops, can not cast err to RaisedErr")
	}
}

func TestErrorBaz(t *testing.T) {
	errs := baz()
	for pos, err := range errs {
		t.Logf("#%d: err -> %v", pos, err)
		if !errors.Is(err, PkgBaseError) {
			t.Errorf("#%d: err is not a noise.Error", pos)
		}
		_, ok := err.(RaisedErr)
		if !ok {
			t.Errorf("#%d: can not cast err to raisedErr", pos)
		}
	}
	err := errs[1]
	if !errors.Is(err, io.EOF) {
		t.Error("Oops, err is not an io.EOF")
	}
}

// ---
// Below definitions show how WrappedError is intended to be used in practice.

// first we define an error type for package error flags
type errorFlag string

// and then at least one global flag error constant
const (
	PkgBaseError = errorFlag("utils: error")
	noError      = errorFlag("")
)

func (self errorFlag) Error() string {
	return string(self)
}

func (self errorFlag) Unwrap() error {
	if noError == self || PkgBaseError == self {
		return nil
	}
	return PkgBaseError
}

// then we define newError & wrapError to be used for all package errors...

func newError(msg string, args ...any) error {
	return NewError(1, PkgBaseError, msg, args...)
}

func wrapError(cause error, msg string, args ...any) error {
	return WrapError(cause, 1, PkgBaseError, msg, args...)
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

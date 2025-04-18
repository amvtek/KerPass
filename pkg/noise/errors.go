package noise

import (
	"fmt"
	"path"
	"runtime"
)

type errorFlag string

const (
	// All package errors are wrapping Error
	Error   = errorFlag("noise: error")
	noError = errorFlag("")
)

func (self errorFlag) Error() string {
	return string(self)
}

func (self errorFlag) Unwrap() error {
	if Error == self || noError == self {
		return nil
	} else {
		return Error
	}
}

type raisedErr struct {
	cause    error
	msg      string
	filename string
	line     int
}

func (self raisedErr) Error() string {
	return fmt.Sprintf("noise: %s\n  file: %s line: %d", self.msg, self.filename, self.line)
}

func (self raisedErr) Unwrap() []error {
	rv := make([]error, 0, 2)
	rv = append(rv, Error)
	if nil != self.cause {
		rv = append(rv, self.cause)
	}
	return rv
}

func newError(msg string, args ...any) error {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	err := raisedErr{msg: msg}
	addCallerFileLine(&err)
	return err
}

func wrapError(cause error, msg string, args ...any) error {
	if nil == cause {
		return nil
	}
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	err := raisedErr{cause: cause, msg: msg}
	addCallerFileLine(&err)
	return err
}

func addCallerFileLine(err *raisedErr) {
	_, filename, line, ok := runtime.Caller(2)
	dirname, filename := path.Split(filename)
	if ok {
		err.filename = path.Join(path.Base(dirname), filename)
		err.line = line
	}
}

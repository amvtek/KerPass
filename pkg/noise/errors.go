package noise

import (
	"fmt"
	"path"
	"runtime"
)

// errorFlag is a private error type that allows declaring error constants.
type errorFlag string

const (
	// All package errors are wrapping Error
	Error                  = errorFlag("noise: error")
	errSizeLimit           = errorFlag("noise: message too large")
	errNoStaticKeyVerifier = errorFlag("noise: missing static key verifier")
	noError                = errorFlag("")
)

// Error implements the error interface.
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

// raisedErr is the type of all package errors.
//
// instances of raisedErr are wrapping the Error flag.
type raisedErr struct {
	cause    error
	msg      string
	filename string
	line     int
}

// Error implements the error interfaces.
func (self raisedErr) Error() string {
	return fmt.Sprintf("noise: %s\n  file: %s line: %d\n%v", self.msg, self.filename, self.line, self.cause)
}

// Unwrap returns a slice that contains the cause of the raisedErr and the global Error flag.
func (self raisedErr) Unwrap() []error {
	rv := make([]error, 0, 2)
	rv = append(rv, Error)
	if nil != self.cause {
		rv = append(rv, self.cause)
	}
	return rv
}

// newError returns a raisedErr{} that contains file & line of where it was called.
func newError(msg string, args ...any) error {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	err := raisedErr{msg: msg}
	addCallerFileLine(&err)
	return err
}

// wrapError returns a raisedErr{} that contains file & line of where it was called.
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

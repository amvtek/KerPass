package protocols

import (
	"errors"

	"code.kerpass.org/golang/internal/utils"
)


// errorFlag is a private error type that allows declaring error constants.
type errorFlag string

const (
	// All package errors are wrapping Error
	Error   = errorFlag("protocols: error")
	OK      = errorFlag("protocols: OK") // error wrapping OK are used to signal protocol completion.
	noError = errorFlag("")
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

// IsError test if err is not protocols.OK
func IsError(err error) bool {
	return (nil != err) && !errors.Is(err, OK)
}

// newError returns a utils.RaisedErr{} that contains file & line of where it was called.
func newError(msg string, args ...any) error {
	return utils.NewError(1, Error, msg, args...)
}

// wrapError returns a utils.RaisedErr{} that contains file & line of where it was called.
func wrapError(cause error, msg string, args ...any) error {
	return utils.WrapError(cause, 1, Error, msg, args...)
}

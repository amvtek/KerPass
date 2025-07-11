package credentials

import (
	"code.kerpass.org/golang/internal/utils"
)

// errorFlag is a private error type that allows declaring error constants.
type errorFlag string

const (
	// All package errors are wrapping Error
	Error             = errorFlag("credentials: error")
	ErrorCardMutation = errorFlag("credentials: Card RealmId & IdToken can not change")
	noError           = errorFlag("")
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

// newError returns a utils.RaisedErr{} that contains file & line of where it was called.
func newError(msg string, args ...any) error {
	return utils.NewError(1, Error, msg, args...)
}

// wrapError returns a utils.RaisedErr{} that contains file & line of where it was called.
func wrapError(cause error, msg string, args ...any) error {
	return utils.WrapError(cause, 1, Error, msg, args...)
}

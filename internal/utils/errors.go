package utils

import (
	"fmt"
	"path"
	"runtime"
)

// RaisedErr is an error type that tracks error occurence location.
// All errors returned by KerPass code base functions are RaisedError instances.
//
// Each package may define a private flag error type and a set of **constants** errors having such types.
// Those flags can be assigned to returned RaisedError to simplify error checking using golang errors.Is.
type RaisedErr struct {
	// Flag allows grouping related errors.
	Flag error

	// Cause is the error that caused the RaisedErr{}.
	Cause error

	// Msg describes what happened.
	Msg string

	// Filename is the source file that contains the code that emitted the error.
	Filename string

	// Line is the location in the source file of the code that emitted the error.
	Line int
}

// Error implements the error interface.
func (self RaisedErr) Error() string {
	return fmt.Sprintf("%s: %s\n  file: %s line: %d\n%v", path.Dir(self.Filename), self.Msg, self.Filename, self.Line, self.Cause)
}

// Unwrap returns a slice that contains the causes of the RaisedErr.
func (self RaisedErr) Unwrap() []error {
	rv := make([]error, 0, 2)
	if nil != self.Flag {
		rv = append(rv, self.Flag)
	}
	if nil != self.Cause {
		rv = append(rv, self.Cause)
	}
	return rv
}

// NewError returns a RaisedErr{} that contains file & line of where it was called.
//
// skip allows controlling Caller frame resolution, if you are calling NewError directly set skip to 0,
// if you are calling NewError from an intermediary newError function set skip to 1...
func NewError(skip int, flag error, msg string, args ...any) error {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	err := RaisedErr{Flag: flag, Msg: msg}
	addCallerFileLine(skip, &err)
	return err
}

// WrapError returns a RaisedErr{} that contains file & line of where it was called.
// If cause is nil, WrapError returns nil.
//
// skip allows controlling Caller frame resolution, if you are calling NewError directly set skip to 0,
// if you are calling NewError from an intermediary newError function set skip to 1...
func WrapError(cause error, skip int, flag error, msg string, args ...any) error {
	if nil == cause {
		return nil
	}
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	err := RaisedErr{Flag: flag, Cause: cause, Msg: msg}
	addCallerFileLine(skip, &err)
	return err
}

func addCallerFileLine(skip int, err *RaisedErr) {
	_, filename, line, ok := runtime.Caller(2 + skip)
	dirname, filename := path.Split(filename)
	if ok {
		err.Filename = path.Join(path.Base(dirname), filename)
		err.Line = line
	}
}

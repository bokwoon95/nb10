package stacktrace

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

func Callers() string {
	var callers []string
	var pc [30]uintptr
	n := runtime.Callers(2, pc[:])
	frames := runtime.CallersFrames(pc[:n])
	for frame, more := frames.Next(); more; frame, more = frames.Next() {
		callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
	}
	var b strings.Builder
	last := len(callers) - 1
	for i := last; i >= 0; i-- {
		if i < last {
			b.WriteString(" -> ")
		}
		b.WriteString(callers[i])
	}
	b.WriteString(": ")
	return b.String()
}

type Error struct {
	Err     error
	Callers []uintptr
}

func WrapError(err error) error {
	_, ok := err.(*Error)
	if ok {
		return err
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	var pc [30]uintptr
	n := runtime.Callers(2, pc[:])
	return &Error{
		Err:     err,
		Callers: pc[:n],
	}
}

func RecoverPanic(err *error) {
	if *err == nil {
		return
	}
	v := recover()
	if v == nil {
		return
	}
	var pc [30]uintptr
	n := runtime.Callers(2, pc[:])
	*err = &Error{
		Err:     fmt.Errorf("%v", v),
		Callers: pc[:n],
	}
}

func (e *Error) Unwrap() error {
	return e.Err
}

func (e *Error) Error() string {
	return e.Err.Error()
}

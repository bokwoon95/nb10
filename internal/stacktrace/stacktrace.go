package stacktrace

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

type Error struct {
	Err     error
	Callers []string
}

func WithCallers(err error) error {
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
	frames := runtime.CallersFrames(pc[:n])
	callers := make([]string, 0, n)
	for frame, more := frames.Next(); more; frame, more = frames.Next() {
		callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
	}
	return &Error{
		Err:     err,
		Callers: callers,
	}
}

func RecoverPanic(err *error) {
	if err == nil {
		return
	}
	if v := recover(); v != nil {
		var pc [30]uintptr
		n := runtime.Callers(2, pc[:])
		frames := runtime.CallersFrames(pc[:n])
		callers := make([]string, 0, n)
		for frame, more := frames.Next(); more; frame, more = frames.Next() {
			callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
		}
		*err = &Error{
			Err:     fmt.Errorf("panic: %v", v),
			Callers: callers,
		}
	}
}

func (e *Error) Unwrap() error {
	return e.Err
}

func (e *Error) Error() string {
	var b strings.Builder
	last := len(e.Callers) - 1
	for i := last; i >= 0; i-- {
		if i < last {
			b.WriteString(" -> ")
		}
		b.WriteString(e.Callers[i])
	}
	if e.Err == nil {
		b.WriteString(": <nil>")
	} else {
		b.WriteString(": " + e.Err.Error())
	}
	return b.String()
}

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

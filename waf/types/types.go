// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package types

import (
	"fmt"
	"io"
	"time"
)

type Rule interface {
	Run(data DataSet, timeout time.Duration) (action Action, info []byte, err error)
	io.Closer
}

// DataSet is a map type to associate binding accessor expressions to their results.
type DataSet map[string]interface{}

type Action int

const (
	NoAction Action = iota
	MonitorAction
	BlockAction
)

type RunError int

const (
	ErrInternal RunError = iota
	ErrTimeout
	ErrInvalidCall
	ErrInvalidRule
	ErrInvalidFlow
	ErrNoRule
	ErrOutOfMemory
)

func (e RunError) Error() string {
	switch e {
	case ErrInternal:
		return "internal error"
	case ErrTimeout:
		return "timeout"
	case ErrInvalidRule:
		return "invalid rule"
	case ErrInvalidCall:
		return "invalid call"
	case ErrInvalidFlow:
		return "invalid flow"
	case ErrNoRule:
		return "no rule"
	case ErrOutOfMemory:
		return "out of memory"
	default:
		return fmt.Sprintf("unknown error `%d`", e)
	}
}

func (e RunError) String() string {
	return e.Error()
}

// Static assertion that the previous error values implement the error interface.
var (
	_ error = ErrInternal
	_ error = ErrTimeout
	_ error = ErrInvalidCall
	_ error = ErrInvalidRule
	_ error = ErrInvalidFlow
	_ error = ErrNoRule
	_ error = ErrOutOfMemory
)

type NewRuleFunc = func(string, string) (Rule, error)
type VersionFunc = func() *string

// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package types

import (
	"io"
	"time"
)

type Rule interface {
	Run(data RunInput, timeout time.Duration) (action Action, info []byte, err error)
	io.Closer
}

// RunInput is a map type whose keys must are binding accessor expressions and
// their result as value.
type RunInput map[string]interface{}

type Action int

const (
	NoAction Action = iota
	MonitorAction
	BlockAction
)

type NewRuleFunc = func(string, string) (Rule, error)

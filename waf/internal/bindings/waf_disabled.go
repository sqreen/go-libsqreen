// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !cgo sqreen_nowaf amd64,windows !amd64

package bindings

import (
	"errors"

	"github.com/sqreen/go-libsqreen/waf/types"
)

func NewRule(id string, rule string) (types.Rule, error) {
	return nil, errors.New("waf disabled at compilation-time because of Go build tags excluding it")
}

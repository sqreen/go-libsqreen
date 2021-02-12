// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !cgo amd64,windows !amd64

package bindings

import (
	"github.com/sqreen/go-libsqreen/waf/types"
)

func NewRule(string) (types.Rule, error) {
	return nil, disabledError
}

func Version() *string { return nil }

func Health() error { return disabledError }

// Static assert that the function have the expected signatures
var (
	_ types.NewRuleFunc = NewRule
	_ types.VersionFunc = Version
	_ types.HealthFunc  = Health
)

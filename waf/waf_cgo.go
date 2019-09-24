// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !libsqreen_plugin

package waf

import (
	"github.com/sqreen/go-libsqreen/waf/internal/bindings"
	"github.com/sqreen/go-libsqreen/waf/types"
)

func newRuleImpl(id, rule string) (types.Rule, error) {
	return bindings.NewRule(id, rule)
}

func version() *string {
	return bindings.Version()
}

// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf

import (
	"github.com/sqreen/go-libsqreen/waf/internal/bindings"
	"github.com/sqreen/go-libsqreen/waf/types"
)

func newRule(rule string) (types.Rule, error) {
	return bindings.NewRule(rule)
}

func newAdditiveContext(r types.Rule) types.Rule {
	return bindings.NewAdditiveContext(r)
}

func version() *string {
	return bindings.Version()
}

func health() error {
	return bindings.Health()
}

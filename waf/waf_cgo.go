// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf

import (
	"github.com/sqreen/go-libsqreen/waf/internal/bindings"
	"github.com/sqreen/go-libsqreen/waf/types"
)

func newRuleImpl(id, rule string, maxLen, maxDepth uint64) (types.Rule, error) {
	return bindings.NewRule(id, rule, maxLen, maxDepth)
}

func version() *string {
	return bindings.Version()
}

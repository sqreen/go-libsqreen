// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf

import "github.com/sqreen/go-libsqreen/waf/types"

func NewRule(id, rule string) (types.Rule, error) {
	return newRuleImpl(id, rule)
}

// Static assert that `NewRule` has the expected signature
var _ types.NewRuleFunc = NewRule

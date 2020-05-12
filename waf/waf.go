// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf

import "github.com/sqreen/go-libsqreen/waf/types"

func NewRule(id, rule string, maxLen, maxDepth uint64) (types.Rule, error) {
	return newRuleImpl(id, rule, maxLen, maxDepth)
}

// Static assert that `NewRule` has the expected signature
var _ types.NewRuleFunc = NewRule

func Version() *string {
	return version()
}

// Static assert that `Version` has the expected signature
var _ types.VersionFunc = Version

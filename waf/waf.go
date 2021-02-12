// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf

import "github.com/sqreen/go-libsqreen/waf/types"

func NewRule(rule string) (types.Rule, error) {
	return newRule(rule)
}

func NewAdditiveContext(r types.Rule) types.Rule {
	return newAdditiveContext(r)
}

func Version() *string {
	return version()
}

func Health() error {
	return health()
}

// Static assert that the function have the expected signatures
var (
	_ types.NewRuleFunc            = NewRule
	_ types.NewAdditiveContextFunc = NewAdditiveContext
	_ types.VersionFunc            = Version
	_ types.HealthFunc             = Health
)

// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build libsqreen_plugin

package waf

import (
	"plugin"
	"sync"

	"github.com/pkg/errors"
	"github.com/sqreen/go-libsqreen/waf/types"
)

var (
	once    sync.Once
	newRule types.NewRuleFunc
)

func newRuleImpl(id, rule string) (types.Rule, error) {
	var err error
	once.Do(func() {
		var (
			p   *plugin.Plugin
			sym plugin.Symbol
		)
		p, err = plugin.Open("waf.so")
		if err != nil {
			return
		}
		sym, err = p.Lookup("NewRule")
		if err != nil {
			return
		}
		newRule = sym.(types.NewRuleFunc)
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not open the waf plugin `waf.so`")
	}
	return newRule(id, rule)
}

func version() *string {
	return nil
}

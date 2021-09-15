// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !cgo !amd64 windows

package waf_test

import (
	"testing"

	"github.com/sqreen/go-libsqreen/waf"
	"github.com/stretchr/testify/require"
)

func TestUsage(t *testing.T) {
	t.Run("rule", func(t *testing.T) {
		r, err := waf.NewRule("")
		require.Nil(t, r)
		require.Error(t, err)
	})

	t.Run("version", func(t *testing.T) {
		require.Nil(t, waf.Version())
	})

	t.Run("health", func(t *testing.T) {
		require.Error(t, waf.Health())
	})
}

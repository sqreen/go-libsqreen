// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !cgo

package bindings

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisabledCGO(t *testing.T) {
	err := Health()
	require.Error(t, err)
	require.Contains(t, err.Error(), "CGO")
}

// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build cgo
// +build windows !amd64

package bindings

import (
	"errors"
)

var disabledError = errors.New("the target system is not supported")

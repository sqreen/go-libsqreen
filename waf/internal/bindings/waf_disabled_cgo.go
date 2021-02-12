// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !cgo

package bindings

import (
	"errors"
)

var disabledError = errors.New("CGO is required but was disabled during the program's compilation")

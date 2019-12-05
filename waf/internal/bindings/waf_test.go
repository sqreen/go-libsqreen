// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package bindings_test

import (
	"testing"
	"unsafe"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
)

func TestCGO(t *testing.T) {
	t.Run("a Go string address is the address of the string buffer", func(t *testing.T) {
		// Create a random string
		var str string
		fuzz.New().NilChance(0).Fuzz(&str)
		require.NotEmpty(t, str)

		// []byte(str) returns a copy of str because slices are mutable while
		// strings are not.
		// So check that it is indeed possible to get the underlying slice of bytes
		// using unsafe.Pointer() casts.
		buf := *(*[]byte)(unsafe.Pointer(&str))
		// The slice should now be usable: len() works and buf[i] gives the string
		// characters
		require.Equal(t, len(buf), len(str))
		for i := range str {
			require.Equal(t, str[i], buf[i])
		}
	})
}

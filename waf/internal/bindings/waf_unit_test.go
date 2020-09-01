// Copyright (c) 2016 - 2020 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !sqreen_nowaf
// +build !windows
// +build amd64
// +build linux darwin

package bindings

import (
	"testing"

	"github.com/sqreen/go-libsqreen/waf/types"
	"github.com/stretchr/testify/require"
)

func TestMarshal(t *testing.T) {
	for _, tc := range []struct {
		Name          string
		Data          types.DataSet
		ExpectedError bool
	}{
		{
			Name: "having a Go function value",
			Data: types.DataSet{
				"f": func() {},
				"i": 33,
			},
			ExpectedError: true,
		},
		{
			Name: "having a int",
			Data: types.DataSet{
				"i": 33,
			},
		},
		{
			Name: "having a float",
			Data: types.DataSet{
				"i": 33.12345,
			},
		},
		{
			Name: "having an array",
			Data: types.DataSet{
				"i": []interface{}{33.12345, "ok", 27},
			},
		},
		{
			Name: "having an array with a bool value",
			Data: types.DataSet{
				"i": []interface{}{33.12345, "ok", 27, true},
			},
		},
		{
			Name: "having a map",
			Data: types.DataSet{
				"i": map[string]interface{}{"k1": 1, "k2": "2"},
			},
		},
		{
			Name: "having a map with wrong key type",
			Data: types.DataSet{
				"i": map[int]interface{}{1: 1, 2: "2"},
			},
			ExpectedError: true,
		},
		{
			Name: "having a struct",
			Data: types.DataSet{
				"s": struct {
					Public  string
					private string
				}{
					Public:  "Public",
					private: "private",
				},
			},
			ExpectedError: true,
		},
		{
			Name: "having a zero value",
			Data: types.DataSet{
				"i": nil,
			},
			ExpectedError: true,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			v, err := marshalWAFValue(tc.Data)
			if tc.ExpectedError {
				require.Error(t, err)
				require.Nil(t, v)
			} else {
				require.NoError(t, err)
				require.NotNil(t, v)
				freeWAFValue(v)
			}
		})
	}
}

func TestFreeWAFValue(t *testing.T) {
	// Test we always panic - not crash the process

	t.Run("nil value", func(t *testing.T) {
		require.Panics(t, func() {
			freeWAFValue(nil)
		})
	})

	t.Run("nil value", func(t *testing.T) {
		require.NotPanics(t, func() {
			freeWAFValue(&WAFValue{})
		})
	})

	//t.Run("corrupted pointer value", func(t *testing.T) {
	//	require.Panics(t, func() {
	//		debug.SetPanicOnFault(true)
	//		var v WAFValue
	//		v.setString(nil, 33)
	//		*(*uintptr)(v.fieldPointer()) = uintptr(0xdeadbeef)
	//		freeWAFValue(&v)
	//	})
	//})
}

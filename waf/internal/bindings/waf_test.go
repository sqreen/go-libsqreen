// Copyright (c) 2016 - 2020 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build cgo
// +build !windows
// +build amd64
// +build linux darwin

package bindings

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/sqreen/go-libsqreen/waf/types"
	"github.com/stretchr/testify/require"
)

func TestNewRule(t *testing.T) {
	r, err := NewRule(`{ oops`)
	require.Error(t, err)
	require.Nil(t, r)
}

func TestMarshal(t *testing.T) {
	for _, tc := range []struct {
		Name                   string
		Data                   interface{}
		ExpectedError          error
		ExpectedWAFValueType   int
		ExpectedWAFValueLength int
		MaxValueDepth          int
		MaxArrayLength         int
		MaxMapLength           int
		MaxStringLength        int
	}{
		{
			Name:          "unsupported type",
			Data:          make(chan struct{}),
			ExpectedError: ErrUnsupportedValue,
		},
		{
			Name:                   "zero time value",
			Data:                   time.Time{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:          "nil interface value",
			Data:          nil,
			ExpectedError: ErrUnsupportedValue,
		},
		{
			Name:          "nil pointer value",
			Data:          (*int)(nil),
			ExpectedError: ErrUnsupportedValue,
		},
		{
			Name:                 "non nil pointer value",
			Data:                 new(int),
			ExpectedWAFValueType: wafStringType, // currently converted into strings by the waf
		},
		{
			Name:                 "non nil pointer value",
			Data:                 new(string),
			ExpectedWAFValueType: wafStringType,
		},
		{
			Name:                   "having an empty dataset",
			Data:                   types.DataSet{},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 0,
		},
		{
			Name:          "a Go function value",
			Data:          func() {},
			ExpectedError: ErrUnsupportedValue,
		},
		{
			Name:                 "int",
			Data:                 int(33),
			ExpectedWAFValueType: wafStringType, // waf internals: number are converted into strings
		},
		{
			Name:                 "uint",
			Data:                 uint(33),
			ExpectedWAFValueType: wafStringType, // waf internals: number are converted into strings
		},
		{
			Name:                 "bool",
			Data:                 true,
			ExpectedWAFValueType: wafStringType, // waf internals: number are converted into strings
		},
		{
			Name:                 "float",
			Data:                 33.12345,
			ExpectedWAFValueType: wafStringType, // waf internals: number are converted into strings
		},
		{
			Name:                   "slice",
			Data:                   []interface{}{33.12345, "ok", 27},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "slice having unsupported types",
			Data:                   []interface{}{33.12345, func() {}, "ok", 27, nil},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "array",
			Data:                   [...]interface{}{func() {}, 33.12345, "ok", 27},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "map",
			Data:                   map[string]interface{}{"k1": 1, "k2": "2"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name:                   "map with invalid key type",
			Data:                   map[interface{}]interface{}{"k1": 1, 27: "int key", "k2": "2"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 2,
		},
		{
			Name:                   "map with indirect string values",
			Data:                   map[interface{}]interface{}{"k1": 1, new(string): "string pointer key", "k2": "2"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name: "struct",
			Data: struct {
				Public  string
				private string
				a       string
				A       string
			}{
				Public:  "Public",
				private: "private",
				a:       "a",
				A:       "A",
			},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 2, // public field only
		},
		{
			Name: "struct with unsupported values",
			Data: struct {
				Public  string
				private string
				a       string
				A       func()
			}{
				Public:  "Public",
				private: "private",
				a:       "a",
				A:       nil,
			},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 1, // public fields of supported types
		},
		{
			Name:                   "array max depth",
			MaxValueDepth:          1,
			Data:                   []interface{}{1, 2, 3, 4, []int{1, 2, 3, 4}},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 4,
		},
		{
			Name:                   "map max depth",
			MaxValueDepth:          1,
			Data:                   map[string]interface{}{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": map[string]string{}},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 4,
		},
		{
			Name:                   "array max length",
			MaxArrayLength:         3,
			Data:                   []interface{}{1, 2, 3, 4, 5},
			ExpectedWAFValueType:   wafArrayType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "map max length",
			MaxMapLength:           3,
			Data:                   map[string]string{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "string max length",
			MaxStringLength:        3,
			Data:                   "123456789",
			ExpectedWAFValueType:   wafStringType,
			ExpectedWAFValueLength: 3,
		},
		{
			Name:                   "string max length truncation leading to same map keys",
			MaxStringLength:        1,
			Data:                   map[string]string{"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5"},
			ExpectedWAFValueType:   wafMapType,
			ExpectedWAFValueLength: 5,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			maxValueDepth := 10
			if max := tc.MaxValueDepth; max != 0 {
				maxValueDepth = max
			}
			maxArrayLength := 1000
			if max := tc.MaxArrayLength; max != 0 {
				maxArrayLength = max
			}
			maxMapLength := 1000
			if max := tc.MaxMapLength; max != 0 {
				maxMapLength = max
			}
			maxStringLength := 4096
			if max := tc.MaxStringLength; max != 0 {
				maxStringLength = max
			}
			m := Encoder{
				MaxValueDepth:   maxValueDepth,
				MaxStringLength: maxStringLength,
				MaxArrayLength:  maxArrayLength,
				MaxMapLength:    maxMapLength,
			}
			v, err := m.marshalWAFValueRec(reflect.ValueOf(tc.Data), 0)
			if tc.ExpectedError != nil {
				require.Error(t, err)
				require.Equal(t, tc.ExpectedError, err)
				require.Equal(t, InvalidWAFValue, v)
				return
			}

			defer v.free()
			require.NoError(t, err)
			require.NotEqual(t, InvalidWAFValue, v)

			if tc.ExpectedWAFValueType != 0 {
				require.Equal(t, tc.ExpectedWAFValueType, int(v._type))
			}
			if tc.ExpectedWAFValueLength != 0 {
				require.Equal(t, tc.ExpectedWAFValueLength, int(v.nbEntries), "waf value type")
			}
		})
	}
}

func TestFreeWAFValue(t *testing.T) {
	// Test we don't crash the process

	t.Run("nil value", func(t *testing.T) {
		require.NotPanics(t, func() {
			(*WAFValue)(nil).free()
		})
	})

	t.Run("nil value", func(t *testing.T) {
		require.NotPanics(t, func() {
			(&WAFValue{}).free()
		})
	})
}

func BenchmarkMarshal(b *testing.B) {
	rnd := rand.New(rand.NewSource(33))
	buf := make([]byte, 16384)
	n, err := rnd.Read(buf)
	fullstr := string(buf)
	marshaler := Encoder{
		MaxValueDepth:   10,
		MaxStringLength: 1 * 1024 * 1024,
		MaxArrayLength:  100,
		MaxMapLength:    100,
	}
	for _, l := range []int{1024, 4096, 8192, 16384} {
		b.Run(fmt.Sprintf("%d", l), func(b *testing.B) {
			str := fullstr[:l]
			slice := []string{str, str, str, str, str, str, str, str, str, str}
			data := types.DataSet{
				"k0": slice,
				"k1": slice,
				"k2": slice,
				"k3": slice,
				"k4": slice,
				"k5": slice,
				"k6": slice,
				"k7": slice,
				"k8": slice,
				"k9": slice,
			}
			if err != nil || n != len(buf) {
				b.Fatal(err)
			}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				v, err := marshaler.marshalWAFValue(data)
				if err != nil {
					b.Fatal(err)
				}
				v.free()
			}
		})
	}
}

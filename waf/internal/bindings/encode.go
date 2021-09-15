// Copyright (c) 2016 - 2020 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !windows
// +build amd64
// +build linux darwin

package bindings

// #include "waf.h"
import "C"

import (
	"errors"
	"math"
	"reflect"
	"unicode"

	"github.com/sqreen/go-libsqreen/waf/types"
)

const (
	wafInvalidType        = C.PWI_INVALID
	wafSignedNumberType   = C.PWI_SIGNED_NUMBER
	wafUnsignedNumberType = C.PWI_UNSIGNED_NUMBER
	wafStringType         = C.PWI_STRING
	wafArrayType          = C.PWI_ARRAY
	wafMapType            = C.PWI_MAP
)

var (
	ErrMaxDepth         = errors.New("max depth reached")
	ErrUnsupportedValue = errors.New("unsupported value")
)

type Encoder struct {
	MaxValueDepth   int
	MaxStringLength int
	MaxArrayLength  int
	MaxMapLength    int
}

func (e *Encoder) marshalWAFValue(data types.DataSet) (WAFValue, error) {
	return e.marshalWAFValueRec(reflect.ValueOf(data), 0)
}

func (e *Encoder) marshalWAFValueRec(data reflect.Value, depth int) (v WAFValue, err error) {
	v = InvalidWAFValue

	if depth > e.MaxValueDepth {
		// Stop traversing and keep v to its current zero value.
		return InvalidWAFValue, ErrMaxDepth
	}

	switch kind := data.Kind(); kind {
	default:
		return InvalidWAFValue, ErrUnsupportedValue

	case reflect.Bool:
		var b uint64
		if data.Bool() {
			b = 1
		}
		return newWAFUInt64(b), nil

	case reflect.Struct:
		return e.marshalWAFStruct(data, depth+1)

	case reflect.Ptr, reflect.Interface:
		// Not accounted in the depth as it has no impact on the value
		// representation
		return e.marshalWAFValueRec(data.Elem(), depth)

	case reflect.String:
		return newWAFString(data.String(), e.MaxStringLength)

	case reflect.Map:
		return e.marshalWAFMap(data, depth+1)

	case reflect.Array, reflect.Slice:
		return e.marshalWAFArray(data, depth+1)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return newWAFInt64(data.Int()), nil

	case reflect.Float32, reflect.Float64:
		return newWAFInt64(int64(math.Round(data.Float()))), nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64:
		return newWAFUInt64(data.Uint()), nil
	}
}

func (e *Encoder) marshalWAFStruct(data reflect.Value, depth int) (v WAFValue, err error) {
	if depth > e.MaxValueDepth {
		return InvalidWAFValue, ErrMaxDepth
	}

	m := newWAFMap()
	defer func() {
		if err != nil {
			m.free()
		}
	}()

	dataT := data.Type()
	nbFields := dataT.NumField()
	for length, i := 0, 0; length < e.MaxMapLength && i < nbFields; i++ {
		field := dataT.Field(i)
		// Skip private fields
		fName := field.Name
		if len(fName) < 1 || unicode.IsLower(rune(fName[0])) {
			continue
		}

		v, err := e.marshalWAFValueRec(data.Field(i), depth)
		if err != nil {
			if isIgnoredValueError(err) {
				continue
			}
			return v, err
		}

		if err := addToMap(&m, fName, &v, e.MaxStringLength); err != nil {
			return InvalidWAFValue, err
		}

		length++
	}

	return m, nil
}

func isIgnoredValueError(err error) bool {
	return err == ErrUnsupportedValue || err == ErrMaxDepth
}

func (e *Encoder) marshalWAFMap(data reflect.Value, depth int) (v WAFValue, err error) {
	if depth > e.MaxValueDepth {
		return InvalidWAFValue, ErrMaxDepth
	}

	m := newWAFMap()
	defer func() {
		if err != nil {
			m.free()
		}
	}()

	// Marshal map entries
	for length, iter := 0, data.MapRange(); length < e.MaxMapLength && iter.Next(); {
		key, ok := getString(iter.Key())
		if !ok {
			continue
		}
		v, err := e.marshalWAFValueRec(iter.Value(), depth)
		if err != nil {
			if isIgnoredValueError(err) {
				continue
			}
			return v, err
		}

		if err := addToMap(&m, key, &v, e.MaxStringLength); err != nil {
			return InvalidWAFValue, err
		}

		length++
	}

	return m, nil
}

func getString(v reflect.Value) (string, bool) {
	for {
		switch v.Kind() {
		default:
			return "", false
		case reflect.String:
			return v.String(), true
		case reflect.Ptr, reflect.Interface:
			if v.IsNil() {
				return "", false
			}
			v = v.Elem()
		}
	}
}

func (e *Encoder) marshalWAFArray(data reflect.Value, depth int) (v WAFValue, err error) {
	if depth > e.MaxValueDepth {
		return InvalidWAFValue, ErrMaxDepth
	}

	a := newWAFArray()
	defer func() {
		if err != nil {
			a.free()
		}
	}()

	// Profiling shows `data.Len()` is called every loop if it is
	// used in the loop condition.
	l := data.Len()
	for length, i := 0, 0; length < e.MaxArrayLength && i < l; i++ {
		v, err := e.marshalWAFValueRec(data.Index(i), depth)
		if err != nil {
			if isIgnoredValueError(err) {
				continue
			}
			return v, err
		}

		if err := addToArray(&a, &v); err != nil {
			return InvalidWAFValue, err
		}

		length++
	}
	return a, nil
}

type WAFValue C.PWArgs

var InvalidWAFValue = WAFValue(C.pw_getInvalid())

func newWAFString(str string, maxLength int) (WAFValue, error) {
	cstr, length := cstring(str, maxLength)
	if cstr == nil {
		return InvalidWAFValue, types.ErrOutOfMemory
	}

	v := C.pw_initString(cstr, C.uint64_t(length))
	// note that the string will be free'd by the WAF itself in pw_freeArgs
	return WAFValue(v), nil
}

// cstring returns the C string of the given Go string `str` with up to
// maxWAFStringSize bytes, along with the string size that was copied.
func cstring(str string, maxLength int) (*C.char, int) {
	// Limit the maximum string size to copy
	l := len(str)
	if l > maxLength {
		l = maxLength
	}
	// Copy the string up to l.
	// The copy is required as the pointer will be stored into the C structures,
	// so using a Go pointer is impossible (and detected by the cgo pointer checks
	// anyway).
	return C.CString(str[:l]), l
}

func newWAFInt64(n int64) WAFValue {
	v := C.pw_createInt(C.int64_t(n))
	return WAFValue(v)
}

func newWAFUInt64(n uint64) WAFValue {
	v := C.pw_createUint(C.uint64_t(n))
	return WAFValue(v)
}

func newWAFArray() WAFValue {
	v := C.pw_createArray()
	return WAFValue(v)
}

func newWAFMap() WAFValue {
	v := C.pw_createMap()
	return WAFValue(v)
}

func (v *WAFValue) free() {
	if v != nil {
		C.pw_freeArg((*C.PWArgs)(v))
	}
}

func addToMap(m *WAFValue, k string, v *WAFValue, maxStringLength int) error {
	ck, ckLen := cstring(k, maxStringLength)
	if !C.pw_addMapNoCopy((*C.PWArgs)(m), ck, C.uint64_t(ckLen), C.PWArgs(*v)) {
		return errors.New("could not add a value to a map")
	}
	return nil
}

func addToArray(a *WAFValue, e *WAFValue) error {
	if !C.pw_addArray((*C.PWArgs)(a), C.PWArgs(*e)) {
		return errors.New("could not add a value to an array")
	}
	return nil
}

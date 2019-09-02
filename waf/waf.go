// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf

import (
	"fmt"
	"reflect"
	"time"
	"unsafe"
)

// #cgo CFLAGS: -I${SRCDIR}/../lib
// #cgo LDFLAGS: -L${SRCDIR}/../lib -lsqreen -lstdc++ -lm
// #include <stdlib.h>
// #include <string.h>
// #include "PowerWAF.h"
import "C"

type Rule struct {
	id *C.char
}

func NewRule(id string, rule []byte) (*Rule, error) {
	rid := C.CString(id)
	crule := C.CBytes(rule)
	defer C.free(crule)
	ok := C.powerwaf_initializePowerWAF(rid, (*C.char)(crule))
	if !ok {
		return nil, fmt.Errorf("could instantiate the waf rule `%s`", id)
	}
	return &Rule{
		id: rid,
	}, nil
}

func (r *Rule) Close() {
	C.powerwaf_clearRule(r.id)
	C.free(unsafe.Pointer(r.id))
}

type Action int

const (
	NoAction      Action = 0
	MonitorAction Action = C.PW_MONITOR
	BlockAction   Action = C.PW_BLOCK
)

type Error int

const (
	ErrInternal    Error = C.PW_ERR_INTERNAL
	ErrTimeout     Error = C.PW_ERR_TIMEOUT
	ErrInvalidCall Error = C.PW_ERR_INVALID_CALL
	ErrInvalidRule Error = C.PW_ERR_INVALID_RULE
	ErrInvalidFlow Error = C.PW_ERR_INVALID_FLOW
	ErrNoRule      Error = C.PW_ERR_NORULE
)

// Static assertion that the previous error values implement the error interface.
var (
	_ error = ErrInternal
	_ error = ErrTimeout
	_ error = ErrInvalidCall
	_ error = ErrInvalidRule
	_ error = ErrInvalidFlow
	_ error = ErrNoRule
)

func (e Error) Error() string {
	switch e {
	case ErrInternal:
		return "internal error"
	case ErrTimeout:
		return "timeout"
	case ErrInvalidRule:
		return "invalid rule"
	case ErrInvalidCall:
		return "invalid call"
	case ErrInvalidFlow:
		return "invalid flow"
	default:
		return "unknown error"
	}
}

func (e Error) String() string {
	return e.Error()
}

// RunInput is a map type whose keys must are binding accessor expressions and
// their result as value.
type RunInput map[string]interface{}

func (r *Rule) Run(data RunInput, timeout time.Duration) (action Action, match []byte, err error) {
	dataIn, err := toWAFInput(data)
	if err != nil {
		return NoAction, nil, err
	}
	defer C.powerwaf_freeInput(dataIn, C.bool(false))

	ret := C.powerwaf_runPowerWAF(r.id, dataIn, C.ulong(timeout/time.Microsecond))
	defer C.powerwaf_freeReturn(ret)

	switch a := ret.action; a {
	case C.PW_GOOD:
		return NoAction, nil, nil

	case C.PW_MONITOR:
		fallthrough
	case C.PW_BLOCK:
		return Action(a), C.GoBytes(unsafe.Pointer(ret.data), C.int(C.strlen(ret.data))), nil

	default:
		return NoAction, nil, Error(a)
	}
}

func toWAFInput(data RunInput) (*C.PWInput, error) {
	return valueToWAFInput(reflect.ValueOf(data))
}

func valueToWAFInput(v reflect.Value) (in *C.PWInput, err error) {
	switch v.Kind() {
	default:
		return nil, fmt.Errorf("unexpected WAF input type `%T`", v.Interface())

	case reflect.Ptr:
		fallthrough
	case reflect.Interface:
		return valueToWAFInput(v.Elem())

	case reflect.String:
		str := v.String()
		cstr := C.CString(str)
		wstr := C.powerwaf_createStringWithLength(cstr, C.size_t(len(str)))
		C.free(unsafe.Pointer(cstr))
		return &wstr, nil

	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("unexpected WAF map key type `%T` instead of `string`", v.Interface())
		}
		m := C.powerwaf_createMap()
		in = &m
		iter := v.MapRange()
		for iter.Next() {
			value, err := valueToWAFInput(iter.Value())
			if err != nil {
				C.powerwaf_freeInput(in, C.bool(false))
				return nil, err
			}
			key := C.CString(iter.Key().String())
			C.powerwaf_addToPWInputMap(in, key, *value)
			C.free(unsafe.Pointer(key))
		}
		return in, nil

	case reflect.Slice:
		a := C.powerwaf_createArray()
		in = &a
		for i := 0; i < v.Len(); i++ {
			value, err := valueToWAFInput(v.Index(i))
			if err != nil {
				C.powerwaf_freeInput(in, C.bool(false))
				return nil, err
			}
			C.powerwaf_addToPWInputArray(in, *value)
		}
		return in, nil
	}
}

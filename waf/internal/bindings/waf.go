// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package bindings

import (
	"errors"
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"github.com/sqreen/go-libsqreen/waf/types"
)

// #cgo CFLAGS: -I${SRCDIR}/../../../lib/include
// #cgo linux amd64 LDFLAGS: -L${SRCDIR}/../../../lib/lib64/
// #cgo LDFLAGS: -lwaf -lstdc++
// #include <stdlib.h>
// #include <string.h>
// #include "waf.h"
// extern void onLogMessage(PW_LOG_LEVEL level, const char *function, const char *file, int line, const char *message, size_t message_len);
import "C"

type Rule struct {
	id *C.char
}

func NewRule(id string, rule string) (types.Rule, error) {
	rid := C.CString(id)
	crule := C.CString(rule)
	defer C.free(unsafe.Pointer(crule))
	ok := C.powerwaf_initializePowerWAF(rid, crule)
	if !ok {
		return nil, fmt.Errorf("could instantiate the waf rule `%s`", id)
	}
	return Rule{
		id: rid,
	}, nil
}

// Static assert that NewRule has the expected signature.
var _ types.NewRuleFunc = NewRule

func (r Rule) Close() error {
	C.powerwaf_clearRule(r.id)
	C.free(unsafe.Pointer(r.id))
	return nil
}

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
	case ErrNoRule:
		return "no rule"
	default:
		return fmt.Sprintf("unknown error `%d`", e)
	}
}

func (e Error) String() string {
	return e.Error()
}

func (r Rule) Run(data types.RunInput, timeout time.Duration) (action types.Action, info []byte, err error) {
	dataIn, err := WAFInput(data)
	if err != nil {
		return 0, nil, err
	}
	defer C.powerwaf_freeInput(dataIn, C.bool(false))

	ret := C.powerwaf_runPowerWAF(r.id, dataIn, C.ulong(timeout/time.Microsecond))
	defer C.powerwaf_freeReturn(ret)

	switch a := ret.action; a {
	case C.PW_GOOD:
		return types.NoAction, nil, nil
	case C.PW_MONITOR:
		action = types.MonitorAction
	case C.PW_BLOCK:
		action = types.BlockAction
	default:
		return 0, nil, Error(a)
	}

	info = C.GoBytes(unsafe.Pointer(ret.data), C.int(C.strlen(ret.data)))
	return action, info, nil
}

func WAFInput(data types.RunInput) (*C.PWArgs, error) {
	return valueToWAFInput(reflect.ValueOf(data))
}

func valueToWAFInput(v reflect.Value) (in *C.PWArgs, err error) {
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
		defer C.free(unsafe.Pointer(cstr))
		wstr := C.powerwaf_createStringWithLength(cstr, C.size_t(len(str)))
		return &wstr, nil

	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("unexpected WAF map key type `%T` instead of `string`", v.Interface())
		}
		m := C.powerwaf_createMap()
		in = &m
		for _, k := range v.MapKeys() {
			value, err := valueToWAFInput(v.MapIndex(k))
			if err != nil {
				C.powerwaf_freeInput(in, C.bool(false))
				return nil, err
			}
			k := k.String()
			key := C.CString(k)
			defer C.free(unsafe.Pointer(key))
			if !C.powerwaf_addToPWArgsMap(in, key, C.ulong(len(k)), *value) {
				C.powerwaf_freeInput(value, C.bool(false))
				C.powerwaf_freeInput(in, C.bool(false))
				return nil, errors.New("could not insert a key element into a map")
			}
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
			if !C.powerwaf_addToPWArgsArray(in, *value) {
				C.powerwaf_freeInput(in, C.bool(false))
				return nil, fmt.Errorf("could not insert element `%d` of an array", i)
			}
		}
		return in, nil

	case reflect.Int:
		fallthrough
	case reflect.Int8:
		fallthrough
	case reflect.Int16:
		fallthrough
	case reflect.Int32:
		fallthrough
	case reflect.Int64:
		arg := C.powerwaf_createInt((C.long)(v.Int()))
		return &arg, nil

	case reflect.Uint:
		fallthrough
	case reflect.Uint8:
		fallthrough
	case reflect.Uint16:
		fallthrough
	case reflect.Uint32:
		fallthrough
	case reflect.Uint64:
		arg := C.powerwaf_createUint((C.ulong)(v.Uint()))
		return &arg, nil
	}
}

//export goOnLogMessage
func goOnLogMessage(level C.PW_LOG_LEVEL, _, _ *C.char, _ C.int, message *C.char, length C.size_t) {
	fmt.Println(C.GoStringN(message, C.int(length)))
}

func SetupLogging() {
	C.powerwaf_setupLogging(C.powerwaf_logging_cb_t(C.onLogMessage), C.PWL_DEBUG)
}

// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !sqreen_nowaf
// +build !windows
// +build amd64
// +build linux darwin

package bindings

import (
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/sqreen/go-libsqreen/waf/types"
)

// #cgo CFLAGS: -I${SRCDIR}
// #cgo LDFLAGS: -L${SRCDIR}
// #cgo amd64,linux LDFLAGS: -l:libwaf_linux_amd64.a -l:libc++_linux_amd64.a -l:libc++abi_linux_amd64.a -l:libunwind_linux_amd64.a -lm -Wl,-rpath=/lib64:/usr/lib64:/usr/local/lib64:/lib:/usr/lib:/usr/local/lib
// #cgo amd64,darwin LDFLAGS: -lwaf_darwin_amd64 -lstdc++
// #include <stdlib.h>
// #include <string.h>
// #include "waf.h"
// extern void onLogMessage(PW_LOG_LEVEL level, const char *function, const char *file, int line, const char *message, size_t message_len);
import "C"

func Version() *string {
	v := C.powerwaf_getVersion()
	major := uint16(v.major)
	minor := uint16(v.minor)
	patch := uint16(v.patch)
	str := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	return &str
}

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

func (r Rule) Run(data types.DataSet, timeout time.Duration) (action types.Action, info []byte, err error) {
	wafValue, err := marshalWAFValue(data)
	if err != nil {
		return 0, nil, err
	}
	defer freeWAFValue(wafValue)

	ret := C.powerwaf_runPowerWAF(r.id, (*C.PWArgs)(wafValue), C.size_t(timeout/time.Microsecond))
	defer C.powerwaf_freeReturn(ret)

	switch a := ret.action; a {
	case C.PW_GOOD:
		return types.NoAction, nil, nil
	case C.PW_MONITOR:
		action = types.MonitorAction
	case C.PW_BLOCK:
		action = types.BlockAction
	default:
		return 0, nil, goRunError(a, ret.data)
	}

	info = C.GoBytes(unsafe.Pointer(ret.data), C.int(C.strlen(ret.data)))
	return action, info, nil
}

func goRunError(cErr C.PW_RET_CODE, data *C.char) error {
	var err error
	switch cErr {
	case C.PW_ERR_INTERNAL:
		err = types.ErrInternal
	case C.PW_ERR_TIMEOUT:
		err = types.ErrTimeout
	case C.PW_ERR_INVALID_CALL:
		err = types.ErrInvalidCall
	case C.PW_ERR_INVALID_RULE:
		err = types.ErrInvalidRule
	case C.PW_ERR_INVALID_FLOW:
		err = types.ErrInvalidFlow
	case C.PW_ERR_NORULE:
		err = types.ErrNoRule
	default:
		err = fmt.Errorf("WAFError(%d)", err)
	}
	if data != nil {
		str := C.GoString(data)
		err = fmt.Errorf("%s: %s", err, str)
	}
	return err
}

type (
	WAFValue    C.PWArgs
	WAFInt      C.PWArgs
	WAFUInt     C.PWArgs
	WAFString   C.PWArgs
	WAFMap      C.PWArgs
	WAFMapEntry C.PWArgs
	WAFArray    C.PWArgs
)

const maxWAFValueDepth = 10

func marshalWAFValue(data types.DataSet) (*WAFValue, error) {
	v := new(WAFValue)
	if err := marshalWAFValueRec(reflect.ValueOf(data), v, maxWAFValueDepth); err != nil {
		freeWAFValue(v)
		return nil, err
	}
	return v, nil
}

func marshalWAFValueRec(data reflect.Value, v *WAFValue, depth int) error {
	if depth == 0 {
		// Stop traversing and keep v to its current zero value.
		return nil
	}

	switch data.Kind() {
	default:
		return fmt.Errorf("unexpected WAF input type `%T`", data.Interface())

	case reflect.Ptr:
		fallthrough
	case reflect.Interface:
		// This interface or pointer traversal is not counted in the depth
		return marshalWAFValueRec(data.Elem(), v, depth)

	case reflect.String:
		return makeWAFString((*WAFString)(v), data.String())

	case reflect.Map:
		if err := makeWAFMap((*WAFMap)(v), data.Len()); err != nil {
			return err
		}
		return marshalWAFMap(data, (*WAFMap)(v), depth-1)

	case reflect.Array:
		fallthrough
	case reflect.Slice:
		if err := makeWAFArray((*WAFArray)(v), data.Len()); err != nil {
			return err
		}
		return marshalWAFArray(data, (*WAFArray)(v), depth-1)

	case reflect.Int:
		fallthrough
	case reflect.Int8:
		fallthrough
	case reflect.Int16:
		fallthrough
	case reflect.Int32:
		fallthrough
	case reflect.Int64:
		return makeWAFInt((*WAFInt)(v), data.Int())

	case reflect.Uint:
		fallthrough
	case reflect.Uint8:
		fallthrough
	case reflect.Uint16:
		fallthrough
	case reflect.Uint32:
		fallthrough
	case reflect.Uint64:
		return makeWAFUInt((*WAFUInt)(v), data.Uint())
	}
}

func marshalWAFMap(data reflect.Value, v *WAFMap, depth int) error {
	// Only allow string key types
	if data.Type().Key().Kind() != reflect.String {
		return errors.Errorf("unexpected WAF map key type `%T` instead of `string`", data.Interface())
	}
	// Marshal map entries
	for i, iter := 0, data.MapRange(); iter.Next(); i++ {
		entry := v.Index(i)
		// Add the key first in order to get key insertion errors before traversing
		// the value. It would be a waste if in the end the key cannot be added.
		key := iter.Key().String()
		if err := makeWAFMapKey(entry, key); err != nil {
			return errors.Wrap(err, "could not add a new map key")
		}
		// Marshal the key's value
		if err := marshalWAFValueRec(iter.Value(), (*WAFValue)(entry), depth); err != nil {
			return err
		}
	}
	return nil
}

func marshalWAFArray(data reflect.Value, v *WAFArray, depth int) error {
	// Profiling shows `data.Len()` is called every loop if it is
	// used in the loop condition.
	l := data.Len()
	for i := 0; i < l; i++ {
		if err := marshalWAFValueRec(data.Index(i), v.Index(i), depth); err != nil {
			return err
		}
	}
	return nil
}

func makeWAFMap(v *WAFMap, len int) error {
	return makeWAFLengthedValue((*WAFValue)(v), len, C.PWI_MAP)
}

func (m *WAFMap) Index(i int) *WAFMapEntry {
	entry := (*WAFArray)(m).Index(i)
	return (*WAFMapEntry)(entry)
}

func (a *WAFArray) Index(i int) *WAFValue {
	if C.uint64_t(i) >= a.nbEntries {
		panic(errors.New("out of bounds access to WAFArray"))
	}
	// Go pointer arithmetic equivalent to the C expression
	// `(PWArgs*)(a->value)[i]`
	return (*WAFValue)(unsafe.Pointer(uintptr(a.value) + C.sizeof_PWArgs*uintptr(i)))
}

func makeWAFMapKey(v *WAFMapEntry, key string) error {
	cstr, length := cstring(key)
	if cstr == nil {
		return types.ErrOutOfMemory
	}
	v.parameterName = cstr
	v.parameterNameLength = C.uint64_t(length)
	return nil
}

func makeWAFArray(v *WAFArray, len int) error {
	return makeWAFLengthedValue((*WAFValue)(v), len, C.PWI_ARRAY)
}

const maxWAFStringSize = 4 * 1024

func makeWAFString(v *WAFString, str string) error {
	cstr, length := cstring(str)
	if cstr == nil {
		return types.ErrOutOfMemory
	}
	v.value = unsafe.Pointer(cstr)
	v.nbEntries = C.uint64_t(length)
	v._type = C.PWI_STRING
	return nil
}

// cstring returns the C string of the given Go string `str` with up to
// maxWAFStringSize bytes, along with the string size that was copied.
func cstring(str string) (*C.char, int) {
	// Limit the maximum string size to copy
	l := len(str)
	if l > maxWAFStringSize {
		l = maxWAFStringSize
	}
	// Copy the string up to l.
	// The copy is required as the pointer will be stored into the C structures,
	// so using a Go pointer is impossible (and detected by the cgo pointer checks
	// anyway).
	return C.CString(str[:l]), l
}

func makeWAFInt(v *WAFInt, n int64) error {
	return makeWAFBasicValue((*WAFValue)(v), uintptr(n), C.PWI_SIGNED_NUMBER)
}

func makeWAFUInt(v *WAFUInt, n uint64) error {
	return makeWAFBasicValue((*WAFValue)(v), uintptr(n), C.PWI_UNSIGNED_NUMBER)
}

func makeWAFBasicValue(v *WAFValue, data uintptr, wafType C.PW_INPUT_TYPE) error {
	v.value = unsafe.Pointer(data)
	v._type = wafType
	return nil
}

func makeWAFLengthedValue(v *WAFValue, len int, wafType C.PW_INPUT_TYPE) error {
	// Allocate the zero'd array.
	a := C.calloc(C.size_t(len), C.sizeof_PWArgs)
	if a == nil {
		return types.ErrOutOfMemory
	}

	v.value = a
	v.nbEntries = C.uint64_t(len)
	v._type = wafType
	return nil
}

func freeWAFValue(v *WAFValue) {
	switch v._type {
	case C.PWI_MAP:
		fallthrough
	case C.PWI_ARRAY:
		for child := 0; C.uint64_t(child) < v.nbEntries; child++ {
			entry := (*WAFArray)(v).Index(child)
			if entry.parameterName != nil {
				C.free(unsafe.Pointer(entry.parameterName))
			}
			freeWAFValue(entry)
		}
	}

	if v.value != nil {
		C.free(v.value)
	}
}

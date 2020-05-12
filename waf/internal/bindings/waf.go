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
// #cgo amd64,linux LDFLAGS: -l:libwaf_linux_amd64.a -l:libc++_linux_amd64.a -l:libc++abi_linux_amd64.a -l:libunwind_linux_amd64.a -lm -ldl -Wl,-rpath=/lib64:/usr/lib64:/usr/local/lib64:/lib:/usr/lib:/usr/local/lib
// #cgo amd64,darwin LDFLAGS: -lwaf_darwin_amd64 -lstdc++
// #include <stdlib.h>
// #include <string.h>
// #include "waf.h"
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

func NewRule(id string, rule string, maxLen, maxDepth uint64) (types.Rule, error) {
	rid := C.CString(id)

	crule := C.CString(rule)
	defer C.free(unsafe.Pointer(crule))

	cfg := &C.PWConfig{
		maxArrayLength: C.uint64_t(maxLen),
		maxMapDepth:    C.uint64_t(maxDepth),
	}

	ok := C.powerwaf_init(rid, crule, cfg)
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

	ret := C.powerwaf_run(r.id, (*C.PWArgs)(wafValue), C.size_t(timeout/time.Microsecond))
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
	WAFString   WAFValue
	WAFMap      C.PWArgs
	WAFMapEntry C.PWArgs
	WAFArray    C.PWArgs

	// Helper type to get or set the union value in `C.PWArgs`.
	// Unions are not supported by CGO for now, and this helper type uses pointer
	// arithmetic to implement its accesses.
)

// Return the pointer to the union field `value`. It can be casted to the union
// type that needs to be accessed.
func (v *WAFValue) fieldPointer() unsafe.Pointer { return unsafe.Pointer((&v.value[0])) }
func (v *WAFValue) arrayPtr() **C.PWArgs         { return (**C.PWArgs)(v.fieldPointer()) }
func (v *WAFValue) int64Ptr() *C.int64_t         { return (*C.int64_t)(v.fieldPointer()) }
func (v *WAFValue) uint64Ptr() *C.uint64_t       { return (*C.uint64_t)(v.fieldPointer()) }
func (v *WAFValue) stringPtr() **C.char          { return (**C.char)(v.fieldPointer()) }

func (v *WAFValue) setString(str *C.char, length C.uint64_t) {
	v._type = C.PWI_STRING
	v.nbEntries = C.uint64_t(length)
	*v.stringPtr() = str
}

func (v *WAFValue) setInt64(n C.int64_t) {
	v._type = C.PWI_SIGNED_NUMBER
	*v.int64Ptr() = n
}

func (v *WAFValue) setUInt64(n C.uint64_t) {
	v._type = C.PWI_UNSIGNED_NUMBER
	*v.uint64Ptr() = n
}

func (v *WAFValue) setVectorContainer(typ C.PW_INPUT_TYPE, length C.size_t) error {
	// Allocate the zero'd array.
	a := (*C.PWArgs)(C.calloc(length, C.sizeof_PWArgs))
	if a == nil {
		return types.ErrOutOfMemory
	}

	v._type = typ
	v.nbEntries = C.uint64_t(length)
	*v.arrayPtr() = a
	return nil
}

func (v *WAFValue) setArrayContainer(length C.size_t) error {
	return v.setVectorContainer(C.PWI_ARRAY, length)
}

func (v *WAFValue) setMapContainer(length C.size_t) error {
	return v.setVectorContainer(C.PWI_MAP, length)
}

func (v *WAFValue) setMapKey(str *C.char, length C.uint64_t) {
	v.parameterName = str
	v.parameterNameLength = length
}

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

	case reflect.Ptr, reflect.Interface:
		// This interface or pointer traversal is not counted in the depth
		return marshalWAFValueRec(data.Elem(), v, depth)

	case reflect.String:
		return makeWAFString(v, data.String())

	case reflect.Map:
		m, err := makeWAFMap(v, uint(data.Len()))
		if err != nil {
			return err
		}
		return marshalWAFMap(data, m, depth-1)

	case reflect.Array, reflect.Slice:
		a, err := makeWAFArray(v, uint(data.Len()))
		if err != nil {
			return err
		}
		return marshalWAFArray(data, a, depth-1)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		makeWAFInt(v, data.Int())
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64:
		makeWAFUInt(v, data.Uint())
		return nil
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

func makeWAFMap(v *WAFValue, len uint) (*WAFMap, error) {
	if err := v.setMapContainer(C.uint64_t(len)); err != nil {
		return nil, err
	}
	return (*WAFMap)(v), nil
}

func (m *WAFMap) Index(i int) *WAFMapEntry {
	entry := (*WAFArray)(m).Index(i)
	return (*WAFMapEntry)(entry)
}

func (a *WAFArray) Index(i int) *WAFValue {
	if C.uint64_t(i) >= a.nbEntries {
		panic(errors.New("out of bounds access to WAFArray"))
	}
	// Go pointer arithmetic equivalent to the C expression `a->value.array[i]`
	base := uintptr(unsafe.Pointer(*(*WAFValue)(a).arrayPtr()))
	return (*WAFValue)(unsafe.Pointer(base + C.sizeof_PWArgs*uintptr(i)))
}

func makeWAFMapKey(v *WAFMapEntry, key string) error {
	cstr, length := cstring(key)
	if cstr == nil {
		return types.ErrOutOfMemory
	}
	(*WAFValue)(v).setMapKey(cstr, C.uint64_t(length))
	return nil
}

const maxWAFStringSize uint = 4 * 1024

func makeWAFString(v *WAFValue, str string) error {
	cstr, length := cstring(str)
	if cstr == nil {
		return types.ErrOutOfMemory
	}

	v.setString(cstr, C.uint64_t(length))
	return nil
}

// cstring returns the C string of the given Go string `str` with up to
// maxWAFStringSize bytes, along with the string size that was copied.
func cstring(str string) (*C.char, uint) {
	// Limit the maximum string size to copy
	l := uint(len(str))
	if l > maxWAFStringSize {
		l = maxWAFStringSize
	}
	// Copy the string up to l.
	// The copy is required as the pointer will be stored into the C structures,
	// so using a Go pointer is impossible (and detected by the cgo pointer checks
	// anyway).
	return C.CString(str[:l]), l
}

func makeWAFInt(v *WAFValue, n int64) {
	v.setInt64(C.int64_t(n))
}

func makeWAFUInt(v *WAFValue, n uint64) {
	v.setUInt64(C.uint64_t(n))
}

func makeWAFArray(v *WAFValue, len uint) (*WAFArray, error) {
	if err := v.setArrayContainer(C.size_t(len)); err != nil {
		return nil, err
	}
	return (*WAFArray)(v), nil

}

func freeWAFValue(v *WAFValue) {
	switch v._type {
	case C.PWI_MAP, C.PWI_ARRAY:
		for child := 0; C.uint64_t(child) < v.nbEntries; child++ {
			entry := (*WAFArray)(v).Index(child)
			if entry.parameterName != nil {
				C.free(unsafe.Pointer(entry.parameterName))
			}
			freeWAFValue(entry)
		}
	}

	if value := *(*unsafe.Pointer)(v.fieldPointer()); value != nil {
		C.free(value)
	}
}

// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !windows
// +build amd64
// +build linux darwin

package bindings

import (
	"context"
	"fmt"
	"reflect"
	"runtime/trace"
	"sync"
	"sync/atomic"
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

// Static assert that the function have the expected signatures
var (
	_ types.NewRuleFunc            = NewRule
	_ types.NewAdditiveContextFunc = NewAdditiveContext
	_ types.VersionFunc            = Version
	_ types.HealthFunc             = Health
)

func Version() *string {
	v := C.pw_getVersion()
	major := uint16(v.major)
	minor := uint16(v.minor)
	patch := uint16(v.patch)
	str := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	return &str
}

func Health() error { return nil }

type (
	Rule struct {
		handle     C.PWHandle
		encoder    Encoder
		refCounter AtomicRefCounter
	}
)

func NewRule(rule string) (types.Rule, error) {
	//sr := stringRef(rule)
	crule := C.CString(rule)
	defer C.free(unsafe.Pointer(crule))
	handle := C.pw_initH(crule, nil, nil)
	if handle == nil {
		return nil, errors.New("could not instantiate the waf rule")
	}

	r := &Rule{
		handle: handle,
		encoder: Encoder{
			MaxValueDepth:   C.PW_MAX_MAP_DEPTH,
			MaxStringLength: C.PW_MAX_STRING_LENGTH,
			MaxArrayLength:  C.PW_MAX_ARRAY_LENGTH,
			MaxMapLength:    C.PW_MAX_ARRAY_LENGTH,
		},
	}
	r.refCounter.init()
	return r, nil
}

func (r *Rule) addRef() (ok bool) {
	return r.refCounter.increment() != 0
}

func (r *Rule) unRef() {
	if r.refCounter.decrement() == 0 {
		// The rule is no longer referenced, we can free its memory
		trace.Log(context.Background(), "sqreen/waf", "rule memory release")
		r.free()
	}
}

// Close the WAF rule. The underlying C memory is released as soon as there are
// no more execution contexts using the rule.
func (r *Rule) Close() error {
	r.unRef()
	// note that we intentionally let additive contexts continue using the rule,
	// the reference counting will do the job and deallocate the memory once every
	// reference disappear
	return nil
}

func (r *Rule) free() {
	C.pw_clearRuleH(r.handle)
	// Set the handle to nil so that unit tests can check this function was called
	r.handle = nil
}

func (r Rule) Run(data types.DataSet, timeout time.Duration) (action types.Action, info []byte, err error) {
	wafValue, err := r.encoder.marshalWAFValue(data)
	if err != nil {
		return 0, nil, err
	}
	defer wafValue.free()

	ret := C.pw_runH(r.handle, C.PWArgs(wafValue), C.size_t(timeout/time.Microsecond))
	defer C.pw_freeReturn(ret)

	return goReturnValues(ret)
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

type AdditiveContext struct {
	rule   *Rule
	handle C.PWAddContext
	mu     sync.Mutex
}

func NewAdditiveContext(r types.Rule) types.Rule {
	rule, _ := r.(*Rule)
	if rule == nil {
		return nil
	}

	if !rule.addRef() {
		return nil
	}

	handle := C.pw_initAdditiveH(rule.handle)
	if handle == nil {
		return nil
	}

	return &AdditiveContext{
		rule:   rule,
		handle: handle,
	}
}

func (c *AdditiveContext) Run(data types.DataSet, timeout time.Duration) (action types.Action, info []byte, err error) {
	wafValue, err := c.rule.encoder.marshalWAFValue(data)
	if err != nil {
		return 0, nil, err
	}

	ret := c.run(wafValue, timeout)
	defer C.pw_freeReturn(ret)

	action, info, err = goReturnValues(ret)
	if err == types.ErrInvalidCall || err == types.ErrTimeout {
		wafValue.free()
	}
	return action, info, err
}

func (c *AdditiveContext) run(data WAFValue, timeout time.Duration) C.PWRet {
	c.mu.Lock()
	defer c.mu.Unlock()
	return C.pw_runAdditive(c.handle, C.PWArgs(data), C.size_t(timeout/time.Microsecond))
}

func (c *AdditiveContext) Close() error {
	trace.Log(context.Background(), "sqreen/waf", "rule additive context memory release")
	C.pw_clearAdditive(c.handle)
	return c.rule.Close()
}

func goReturnValues(ret C.PWRet) (action types.Action, info []byte, err error) {
	switch a := ret.action; a {
	case C.PW_GOOD:
		return types.NoAction, nil, nil
	case C.PW_MONITOR:
		action = types.MonitorAction
	case C.PW_BLOCK:
		action = types.BlockAction
	default:
		return types.NoAction, nil, goRunError(a, ret.data)
	}
	info = C.GoBytes(unsafe.Pointer(ret.data), C.int(C.strlen(ret.data)))
	return action, info, err
}

type AtomicRefCounter uint32

func (i *AtomicRefCounter) unwrap() *uint32 {
	return (*uint32)(i)
}

func (i *AtomicRefCounter) init() {
	atomic.StoreUint32(i.unwrap(), 1)
}

func (i *AtomicRefCounter) add(delta uint32) uint32 {
	return atomic.AddUint32(i.unwrap(), delta)
}

// CAS implementation in order to enforce no one can +1 right after the -1
// leading to 0 was done. For example, in the case of the WAF rule, the rule
// ref counter is decremented when receiving another WAF rule; meantime, a
// request can try to increment it when creating a WAF additive context:
//   1. Rule reload: counter reaches 0 and the memory is free'd
//   2. A request might still reference the now free'd WAF rule, and we now
//      need to avoid acccepting to increment the counter again to 1.
// 0 is magic number saying it is free'd and the protected value should no
// longer be used.
func (i *AtomicRefCounter) increment() uint32 {
	addr := i.unwrap()
	for {
		current := atomic.LoadUint32(addr)
		if current == 0 {
			// The object was released
			return 0
		}
		new := current + 1
		if swapped := atomic.CompareAndSwapUint32(addr, current, new); swapped {
			return new
		}
	}
}

func (i *AtomicRefCounter) decrement() uint32 {
	const d = ^uint32(0)
	return i.add(d)
}

type stringRefType struct {
	gostr string
	buf   *C.char
	len   int
}

// Return the C-compatible string buffer and length. A reference to the Go
// string must be kept during its usage in C code. Note that the string is not
// null-terminated.
func stringRef(s string) stringRefType {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return stringRefType{
		gostr: s,
		buf:   (*C.char)(unsafe.Pointer(sh.Data)),
		len:   sh.Len,
	}
}

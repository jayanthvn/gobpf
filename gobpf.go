package gobpf

/*
#cgo LDFLAGS: -lelf -lz

#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef MAX_ERRNO
#define MAX_ERRNO           4095
#define IS_ERR_VALUE(x)     ((x) >= (unsigned long)-MAX_ERRNO)

static inline bool IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
    return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR(const void *ptr)
{
    return (long) ptr;
}
#endif

int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                    va_list args)
{
    if (level != LIBBPF_WARN)
        return 0;

	va_list check; va_copy(check, args);
	char *str = va_arg(check, char *);
	if (strstr(str, "Exclusivity flag on") != NULL) {
		va_end(check);
		return 0;
	}
	va_end(check);

    return vfprintf(stderr, format, args);
}

void set_print_fn() {
    libbpf_set_print(libbpf_print_fn);
}
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

type BPFObject struct {
	obj      *C.struct_bpf_object
}

func bumpMemlockRlimit() error {
	var rLimit syscall.Rlimit
	rLimit.Max = 512 << 20 /* 512 MBs */
	rLimit.Cur = 512 << 20 /* 512 MBs */
	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rLimit)
	if err != nil {
		return fmt.Errorf("error setting rlimit: %v", err)
	}
	return nil
}

func errptrError(ptr unsafe.Pointer, format string, args ...interface{}) error {
	negErrno := C.PTR_ERR(ptr)
	errno := syscall.Errno(-int64(negErrno))
	if errno == 0 {
		return fmt.Errorf(format, args...)
	}

	args = append(args, errno.Error())
	return fmt.Errorf(format+": %v", args...)
}

func NewBPFObject(bpfObjPath string) (*BPFObject, error) {
	C.set_print_fn()
	if err := bumpMemlockRlimit(); err != nil {
		return nil, err
	}
	opts := C.struct_bpf_object_open_opts{}
	opts.sz = C.sizeof_struct_bpf_object_open_opts

	bpfFile := C.CString(bpfObjPath)
	defer C.free(unsafe.Pointer(bpfFile))

	obj := C.bpf_object__open_file(bpfFile, &opts)
	if C.IS_ERR_OR_NULL(unsafe.Pointer(obj)) {
		return nil, errptrError(unsafe.Pointer(obj), "failed to open BPF object %s", bpfObjPath)
	}

	return &BPFObject{
		obj: obj,
	}, nil
}


func (m *BPFObject) Close() {
	C.bpf_object__close(m.obj)
}

func (m *BPFObject) BPFLoadObject() error {
	ret := C.bpf_object__load(m.obj)
	if ret != 0 {
		return fmt.Errorf("failed to load BPF object")
	}

	return nil
}

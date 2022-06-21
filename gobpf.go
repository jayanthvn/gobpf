package gobpf
/*
#cgo LDFLAGS: -lelf -lz

#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

//From linux/err.h
#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR(const void *ptr)
{
    return (long) ptr;
}

*/
import "C"

import (
	"fmt"
//	"net"
//	"path/filepath"
//	"sync"
	"syscall"
	"unsafe"
)

func errptrError(ptr unsafe.Pointer, format string, args ...interface{}) error {
	negErrno := C.PTR_ERR(ptr)
	errno := syscall.Errno(-int64(negErrno))
	if errno == 0 {
		return fmt.Errorf(format, args...)
	}

	args = append(args, errno.Error())
	return fmt.Errorf(format+": %v", args...)
}

func BPFObjectOpenFile(filePath string) (*C.struct_bpf_object, error){

	opts := C.struct_bpf_object_open_opts{}

	bpfFile := C.CString(filePath)
	defer C.free(unsafe.Pointer(bpfFile))

	obj := C.bpf_object__open_file(bpfFile, &opts)
	if C.IS_ERR_OR_NULL(unsafe.Pointer(obj)) {
		return nil, errptrError(unsafe.Pointer(obj), "failed to open BPF object %s", filePath)
	}
        return obj, nil
}

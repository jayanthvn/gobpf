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

int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                    va_list args)
{
    FILE *fp;
    fp = fopen("/var/log/aws-routed-eni/file.txt","a+");	
    vfprintf(fp, format, args);
    fclose(fp);
    return vfprintf(stderr, format, args);
}

void set_print_fn() {
    libbpf_set_print(libbpf_print_fn);
}

long libbpf_error(const void *ptr) {
	return libbpf_get_error(ptr);
}

struct bpf_object *bpf_object_open_file(const char *path, const struct bpf_object_open_opts *opts) {
	return bpf_object__open_file(path, opts);
}
*/
import "C"

import (
	"fmt"
	"net"
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

// BPF is using locked memory for BPF maps and various other things.
// By default, this limit is very low - increase to avoid failures
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

type BPFObject struct {
	obj      *C.struct_bpf_object
}

func BPFObjectOpenFile(filePath string) (*BPFObject, error){

	C.set_print_fn()
	if err := bumpMemlockRlimit(); err != nil {
		return nil, err
	}
	opts := C.struct_bpf_object_open_opts{}
	opts.sz = C.sizeof_struct_bpf_object_open_opts

	bpfFile := C.CString(filePath)
	defer C.free(unsafe.Pointer(bpfFile))

	if C.IS_ERR_OR_NULL(unsafe.Pointer(bpfFile)) {
		return nil, errptrError(unsafe.Pointer(bpfFile), "NULL pointer %s", filePath)
	}
	obj := C.bpf_object__open_file(bpfFile, &opts)
	err := C.libbpf_error(unsafe.Pointer(obj))
        if (err != 0) {
		return nil, errptrError(unsafe.Pointer(obj), "LIBPF returned error %d", err) 
	}
	if C.IS_ERR_OR_NULL(unsafe.Pointer(obj)) {
		return nil, errptrError(unsafe.Pointer(obj), "failed to open BPF object %s", filePath)
	}
        return &BPFObject{ 
		obj: obj, 
	}, nil
}

func BPFObjectClose(bpfObject *BPFObject) {
	C.bpf_object__close(bpfObject.obj)
}

func BPFObjectLoad(bpfObject *C.struct_bpf_object) error {
	ret := C.bpf_object__load(bpfObject)
	if ret != 0 {
		return fmt.Errorf("failed to load BPF object")
	}

	return nil
}

func GetProgramByName(progName string, bpfObject *C.struct_bpf_object) (*C.struct_bpf_program, error) {
	progNameStr := C.CString(progName)
	prog, errC := C.bpf_object__find_program_by_name(bpfObject, progNameStr)
	C.free(unsafe.Pointer(progNameStr))
	if prog == nil {
		return nil, fmt.Errorf("failed to find BPF program %s: %w", progName, errC)
	}
        return prog, nil
}

func AttachXDP(deviceName string, prog *C.struct_bpf_program) (error) {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return fmt.Errorf("failed to find device by name %s: %w", deviceName, err)
	}
	link := C.bpf_program__attach_xdp(prog, C.int(iface.Index))
	if C.IS_ERR_OR_NULL(unsafe.Pointer(link)) {
		return errptrError(unsafe.Pointer(link), "failed to attach xdp on device %s", deviceName)
	}
	return nil
}

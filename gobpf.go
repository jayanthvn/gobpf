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
    //if (level != LIBBPF_WARN)
    //    return 0;

	va_list check; va_copy(check, args);
	char *str = va_arg(check, char *);
	if (strstr(str, "Exclusivity flag on") != NULL) {
		va_end(check);
		return 0;
	}
	va_end(check);

    return vfprintf(stderr, format, args);
}

int fileOpen(char *filename, char *mode, FILE **fp) {
      *fp = fopen(filename, mode);
      if (*fp == NULL)
              return -1;
      return 0;
}

int fileclose(FILE *fp) {
      fclose(fp);
      return 0;
}

void set_print_fn() {
    libbpf_set_print(libbpf_print_fn);
}
*/
import "C"

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
	"os"
	"bytes"
	"io"
	"log"
)

const (
	libBpfDebugFile = "/var/log/aws-routed-eni/file.txt"
)

type BPFObject struct {
	obj      *C.struct_bpf_object
}

type BPFProgram struct {
	prog     *C.struct_bpf_program
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

	// Clone Stdout to origStdout.
	origStdout, err := syscall.Dup(syscall.Stdout)
	if err != nil {
		log.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		log.Fatal(err)
	}

	// Clone the pipe's writer to the actual Stdout descriptor; from this point
	// on, writes to Stdout will go to w.
	if err = syscall.Dup2(int(w.Fd()), syscall.Stdout); err != nil {
		log.Fatal(err)
	}

	// Background goroutine that drains the reading end of the pipe.
	out := make(chan []byte)
	go func() {
		var b bytes.Buffer
		io.Copy(&b, r)
		out <- b.Bytes()
	}()
//Above not needed, only for debug
	ret := C.bpf_object__load(m.obj)
	if ret != 0 {
		return fmt.Errorf("failed to load BPF object")
	}
//Below only for debug
        // Cleanup
	C.fflush(nil)
	w.Close()
	syscall.Close(syscall.Stdout)

	// Rendezvous with the reading goroutine.
	b := <-out

	// Restore original Stdout.
	syscall.Dup2(origStdout, syscall.Stdout)
	syscall.Close(origStdout)

	fmt.Println("Captured:", string(b))
	return nil
}

func (m *BPFObject) GetProgramByName(progName string) (*BPFProgram, error) {
	progNameStr := C.CString(progName)
	prog, errC := C.bpf_object__find_program_by_name(m.obj, progNameStr)
	C.free(unsafe.Pointer(progNameStr))
	if prog == nil {
		return nil, fmt.Errorf("failed to find BPF program %s: %w", progName, errC)
	}
        return &BPFProgram{
		prog:prog, 
	}, nil
}

func (p *BPFProgram)AttachXDP(deviceName string) (error) {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return fmt.Errorf("failed to find device by name %s: %w", deviceName, err)
	}
	link := C.bpf_program__attach_xdp(p.prog, C.int(iface.Index))
	if C.IS_ERR_OR_NULL(unsafe.Pointer(link)) {
		return errptrError(unsafe.Pointer(link), "failed to attach xdp on device %s", deviceName)
	}
	return nil
}

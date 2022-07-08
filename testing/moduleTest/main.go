package main

import "C"

import (
	"fmt"
	"os"
        "time"
	jaybpf "github.com/jayanthvn/gobpf"
)

func main() {
	
	bpfObject, err := jaybpf.NewBPFObject("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfObject.Close()
	err = bpfObject.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	xdpProg, err := bpfObject.GetProgramByName("target")
	if xdpProg == nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	fmt.Fprintln(os.Stdout, "found prog name")
        time.Sleep(6 * time.Second)
	err = xdpProg.AttachXDP("eth0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
}

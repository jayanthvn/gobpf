package main

import "C"

import (
	"fmt"
	"os"

	jaybpf "github.com/jayanthvn/gobpf"
)

func main() {
	
	bpfObject, err := jaybpf.NewBPFObject("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfObject.Close()
}

BASEDIR = $(abspath ../../)

OUTPUT = ../../output

LIBBPF_SRC = $(abspath ../../libbpf/src)
LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf.a)

CC = gcc
CLANG = clang
GO = go

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

CFLAGS = -g -O2 -Wall -fpie
LDFLAGS =

CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT))"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'

CGO_CFGLAGS_DYN = "-I. -I/usr/include/"
CGO_LDFLAGS_DYN = "-lelf -lz -lbpf"

.PHONY: $(TEST)
.PHONY: $(TEST).go
.PHONY: $(TEST).bpf.c

TEST = main

all: $(TEST)-static

.PHONY: libbpfgo
.PHONY: libbpfgo-static

## libbpfgo

libbpfgo-static:
	$(MAKE) -C $(BASEDIR) build-libbpf

vmlinuxh:
	$(MAKE) -C $(BASEDIR) vmlinuxh

outputdir:
	$(MAKE) -C $(BASEDIR) outputdir

## test bpf dependency

.PHONY: build-test

build-test: $(TEST).bpf.o
       	
$(TEST).bpf.o: $(TEST).bpf.c
	$(MAKE) -C $(BASEDIR) vmlinuxh
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUTPUT) -c $< -o $@

## test

.PHONY: $(TEST)-static

CGO_CFLAGS_STATIC_JAY = "-I/local/home/varavaj/github/aqua_bpf/libbpfgo/output"
CGO_LDFLAGS_STATIC_JAY = "-lelf -lz /local/home/varavaj/github/aqua_bpf/libbpfgo/output/libbpf.a"
$(TEST)-static: build-test | libbpfgo-static
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
		GOOS=linux GOARCH=$(ARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
		-o $(TEST)-static ./$(TEST).go

## run

.PHONY: run
.PHONY: run-static

run: run-static

run-static: $(TEST)-static
	sudo ./run.sh $(TEST)-static

clean:
	rm -f *.o *-static

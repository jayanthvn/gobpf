//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int target(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
